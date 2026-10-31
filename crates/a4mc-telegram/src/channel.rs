//! The Telegram channel's normalized `a4mc` surface.
//!
//! [`TelegramChannel`] wraps a [`BotTransport`] and exposes the contract
//! surface: a [`ChannelDescriptor`] declaring what this dialect lowers,
//! and `send` lowering [`OutboundMessage`] onto `sendMessage` — including
//! adapter-side idempotency dedupe, since the Bot API has no native key.
//! A key is reserved while its send is in flight and resolved to the
//! observed receipt when it completes; a repeat send joins the in-flight
//! attempt or replays the receipt instead of double-posting.

use crate::transport::BotTransport;
use a4mc::{
    ChannelAdapter, ChannelDescriptor, ChannelError, ChannelId, ExternalMessageId, LaneMechanism,
    OutboundMessage, SendFeature, SendReceipt, Support, UpdateKind,
};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex};

/// The channel identifier this dialect lowers under.
pub const CHANNEL: &str = "telegram";

/// Bound on remembered send receipts — generous headroom over one
/// channel's send rate; oldest entries evict FIFO.
const IDEMPOTENCY_CACHE_CAP: usize = 1024;

/// The dialect's declared capability report. Message and edited-message
/// receive are native (`getUpdates` long polling); the Bot API also
/// offers a webhook mechanism this dialect does not implement — declared
/// unsupported, not silently dropped. Deletion is never reported by the
/// platform; member and reaction updates exist but are not wired yet.
pub fn descriptor() -> ChannelDescriptor {
    ChannelDescriptor {
        channel: ChannelId::from(CHANNEL),
        receive: BTreeMap::from([
            (LaneMechanism::Poll, Support::Native),
            (LaneMechanism::Webhook, Support::Unsupported),
            (LaneMechanism::Socket, Support::Unsupported),
        ]),
        updates: BTreeMap::from([
            (UpdateKind::Message, Support::Native),
            (UpdateKind::MessageEdited, Support::Native),
            (UpdateKind::MessageDeleted, Support::Unsupported),
            (UpdateKind::MemberJoined, Support::Unsupported),
            (UpdateKind::MemberLeft, Support::Unsupported),
            (UpdateKind::Reaction, Support::Unsupported),
        ]),
        sends: BTreeMap::from([
            (SendFeature::Idempotency, Support::Adapted),
            (SendFeature::ReplyTo, Support::Native),
            (SendFeature::Edit, Support::Unsupported),
            (SendFeature::Delete, Support::Unsupported),
        ]),
    }
}

/// The normalized channel surface over one Bot API transport.
pub struct TelegramChannel<T: BotTransport> {
    transport: Arc<T>,
    sent_keys: Mutex<IdempotencyCache>,
    /// Wakes sends parked on an in-flight reservation; paired with the
    /// `sent_keys` mutex.
    send_wake: Condvar,
}

/// One idempotency-key slot: a reservation held across an in-flight
/// send, or the receipt of an observed send.
#[derive(Clone)]
enum SendState {
    InFlight,
    Done(SendReceipt),
}

struct IdempotencyCache {
    /// FIFO order of *completed* keys for eviction — in-flight
    /// reservations never occupy capacity and are never evicted.
    order: VecDeque<String>,
    entries: HashMap<String, SendState>,
}

impl IdempotencyCache {
    fn new() -> Self {
        Self {
            order: VecDeque::new(),
            entries: HashMap::new(),
        }
    }

    fn get(&self, key: &str) -> Option<SendState> {
        self.entries.get(key).cloned()
    }

    fn mark_in_flight(&mut self, key: String) {
        self.entries.insert(key, SendState::InFlight);
    }

    fn complete(&mut self, key: String, receipt: SendReceipt) {
        while self.order.len() >= IDEMPOTENCY_CACHE_CAP {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        self.order.push_back(key.clone());
        self.entries.insert(key, SendState::Done(receipt));
    }

    /// Drop a reservation whose send failed: only *observed* sends are
    /// deduped, so a failed attempt frees the key for its waiters or a
    /// later retry to perform their own transport call.
    fn release(&mut self, key: &str) {
        self.entries.remove(key);
    }
}

impl<T: BotTransport> TelegramChannel<T> {
    pub fn new(transport: Arc<T>) -> Self {
        Self {
            transport,
            sent_keys: Mutex::new(IdempotencyCache::new()),
            send_wake: Condvar::new(),
        }
    }

    pub fn transport(&self) -> &Arc<T> {
        &self.transport
    }

    /// Send one normalized outbound message.
    ///
    /// The contract validates first; the idempotency key is then reserved
    /// under the cache lock *before* the transport call, so check-and-send
    /// is atomic: a repeat key while a send is in flight waits on
    /// `send_wake` and replays the observed receipt instead of posting a
    /// duplicate (adapter-side dedupe — the platform itself has no key,
    /// which is why the descriptor marks idempotency `Adapted`). A failed
    /// send releases its reservation: dedupe covers observed sends only,
    /// so the waiter then performs its own transport call rather than
    /// pinning the key to someone else's failure. Reply targets and
    /// platform id shapes lower here, never inside the transport.
    pub fn send(&self, outbound: &OutboundMessage) -> Result<SendReceipt, ChannelError> {
        outbound.validate()?;
        let chat_id: i64 = outbound
            .chat_id
            .as_str()
            .parse()
            .map_err(|_| ChannelError {
                code: "a4mc_telegram_chat_id_invalid".to_owned(),
                message: "chat id is not a Telegram integer".to_owned(),
            })?;
        let reply_to = outbound
            .reply_to_message_id
            .as_ref()
            .map(|id| {
                id.as_str().parse::<i64>().map_err(|_| ChannelError {
                    code: "a4mc_telegram_message_id_invalid".to_owned(),
                    message: "reply target is not a Telegram message id".to_owned(),
                })
            })
            .transpose()?;
        {
            let mut cache = self.sent_keys.lock().unwrap();
            loop {
                match cache.get(&outbound.idempotency_key) {
                    Some(SendState::Done(receipt)) => return Ok(receipt),
                    Some(SendState::InFlight) => {
                        cache = self.send_wake.wait(cache).unwrap();
                    }
                    None => {
                        cache.mark_in_flight(outbound.idempotency_key.clone());
                        break;
                    }
                }
            }
        }
        match self
            .transport
            .send_message(chat_id, &outbound.text, reply_to)
        {
            Ok(message_ids) => {
                let receipt = SendReceipt {
                    idempotency_key: outbound.idempotency_key.clone(),
                    message_ids: message_ids
                        .into_iter()
                        .map(ExternalMessageId::from)
                        .collect(),
                };
                self.sent_keys
                    .lock()
                    .unwrap()
                    .complete(outbound.idempotency_key.clone(), receipt.clone());
                self.send_wake.notify_all();
                Ok(receipt)
            }
            Err(error) => {
                self.sent_keys
                    .lock()
                    .unwrap()
                    .release(&outbound.idempotency_key);
                self.send_wake.notify_all();
                Err(ChannelError::from(error))
            }
        }
    }
}

impl<T: BotTransport> ChannelAdapter for TelegramChannel<T> {
    fn descriptor(&self) -> ChannelDescriptor {
        descriptor()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{BotIdentity, MockBotTransport, TelegramApiError, Update};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    fn channel() -> (TelegramChannel<MockBotTransport>, Arc<MockBotTransport>) {
        let transport = Arc::new(MockBotTransport::default());
        let channel = TelegramChannel::new(Arc::clone(&transport));
        (channel, transport)
    }

    fn wait_until<F: Fn() -> bool>(condition: F, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while !condition() {
            assert!(Instant::now() < deadline, "condition timed out");
            thread::sleep(Duration::from_millis(2));
        }
    }

    /// A mock whose `send_message` parks until the test releases it, so a
    /// second same-key send provably arrives while the first is in flight.
    struct GatedSendTransport {
        inner: MockBotTransport,
        entered: Arc<AtomicBool>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }

    impl BotTransport for GatedSendTransport {
        fn get_me(&self) -> Result<BotIdentity, TelegramApiError> {
            self.inner.get_me()
        }
        fn delete_webhook(&self) -> Result<(), TelegramApiError> {
            self.inner.delete_webhook()
        }
        fn set_my_commands(&self, commands: &[(String, String)]) -> Result<(), TelegramApiError> {
            self.inner.set_my_commands(commands)
        }
        fn get_updates(
            &self,
            offset: i64,
            timeout_secs: u64,
        ) -> Result<Vec<Update>, TelegramApiError> {
            self.inner.get_updates(offset, timeout_secs)
        }
        fn send_message(
            &self,
            chat_id: i64,
            text: &str,
            reply_to_message_id: Option<i64>,
        ) -> Result<Vec<i64>, TelegramApiError> {
            self.entered.store(true, Ordering::SeqCst);
            let (mutex, condvar) = &*self.release;
            let mut released = mutex.lock().unwrap();
            while !*released {
                released = condvar.wait(released).unwrap();
            }
            drop(released);
            self.inner.send_message(chat_id, text, reply_to_message_id)
        }
    }

    #[test]
    fn descriptor_declares_gaps_honestly() {
        let report = descriptor();
        assert_eq!(report.channel.as_str(), "telegram");
        assert_eq!(report.receive_support(LaneMechanism::Poll), Support::Native);
        assert_eq!(
            report.receive_support(LaneMechanism::Webhook),
            Support::Unsupported
        );
        assert_eq!(report.update_support(UpdateKind::Message), Support::Native);
        assert_eq!(
            report.update_support(UpdateKind::MessageDeleted),
            Support::Unsupported
        );
        assert_eq!(
            report.send_support(SendFeature::Idempotency),
            Support::Adapted
        );
        assert_eq!(report.send_support(SendFeature::ReplyTo), Support::Native);
    }

    #[test]
    fn send_lowers_contract_and_returns_platform_ids() {
        let (channel, transport) = channel();
        let mut outbound = OutboundMessage::new("42", "hello", "send-1");
        outbound.reply_to_message_id = Some(a4mc::ExternalMessageId::from("7"));
        let receipt = channel.send(&outbound).unwrap();
        assert_eq!(receipt.idempotency_key, "send-1");
        assert_eq!(receipt.message_ids.len(), 1);
        assert_eq!(transport.sent.lock().unwrap().len(), 1);
        assert_eq!(transport.sent.lock().unwrap()[0].0, 42);
    }

    #[test]
    fn repeated_idempotency_key_does_not_double_post() {
        let (channel, transport) = channel();
        let outbound = OutboundMessage::new("42", "hello", "send-dup");
        let first = channel.send(&outbound).unwrap();
        let second = channel.send(&outbound).unwrap();
        assert_eq!(first, second);
        assert_eq!(transport.sent.lock().unwrap().len(), 1);
    }

    #[test]
    fn concurrent_same_key_send_posts_once_and_shares_one_receipt() {
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let inner = MockBotTransport::default();
        let sent = Arc::clone(&inner.sent);
        let channel = Arc::new(TelegramChannel::new(Arc::new(GatedSendTransport {
            inner,
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        })));

        let first = {
            let channel = Arc::clone(&channel);
            thread::spawn(move || channel.send(&OutboundMessage::new("42", "hello", "send-race")))
        };
        wait_until(|| entered.load(Ordering::SeqCst), Duration::from_secs(5));
        let second = {
            let channel = Arc::clone(&channel);
            thread::spawn(move || channel.send(&OutboundMessage::new("42", "hello", "send-race")))
        };
        // Give the second send its window to reach the in-flight wait
        // before the first completes.
        thread::sleep(Duration::from_millis(50));
        {
            let (mutex, condvar) = &*release;
            *mutex.lock().unwrap() = true;
            condvar.notify_all();
        }
        let first = first.join().unwrap().unwrap();
        let second = second.join().unwrap().unwrap();
        assert_eq!(first, second);
        assert_eq!(sent.lock().unwrap().len(), 1);
    }

    #[test]
    fn invalid_sends_and_non_telegram_ids_are_rejected() {
        let (channel, _transport) = channel();
        assert!(channel.send(&OutboundMessage::new("42", "", "k")).is_err());
        assert!(channel.send(&OutboundMessage::new("42", "x", " ")).is_err());
        assert_eq!(
            channel
                .send(&OutboundMessage::new("not-a-chat", "x", "k"))
                .unwrap_err()
                .code,
            "a4mc_telegram_chat_id_invalid"
        );
    }
}
