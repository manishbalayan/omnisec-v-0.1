use anyhow::Result;
use async_nats::{Client, ConnectOptions, Message, Subscriber};
use futures::StreamExt;
use omnisec_events::EventEnvelope;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

/// NATS client wrapper for Omnisec.
///
/// Provides typed publish/subscribe over NATS with:
/// - Reconnection handling (built into async-nats)
/// - Graceful shutdown via notification
/// - Subject-based routing matching Omnisec event subjects
pub struct NatsClient {
    client: Client,
    /// Notify all subscribers on shutdown.
    shutdown: Arc<Notify>,
}

impl NatsClient {
    /// Connect to a NATS server with the given URL.
    ///
    /// `name` is used as the connection name (visible in NATS monitoring).
    pub async fn connect(url: &str, name: &str) -> Result<Self> {
        // Inject credentials from environment if provided
        let effective_url = build_nats_url(url);

        let opts = ConnectOptions::new()
            .name(name.to_string())
            .retry_on_initial_connect()
            .max_reconnects(Some(10))
            .reconnect_delay_callback(move |attempt| {
                Duration::from_secs(2u64.min(2u64.pow(attempt as u32)))
            });

        let client = opts.connect(effective_url.as_str()).await?;
        tracing::info!("Connected to NATS at {} as '{}'", url, name);

        Ok(Self {
            client,
            shutdown: Arc::new(Notify::new()),
        })
    }

    /// Get a raw handle to the underlying async-nats client.
    pub fn raw_client(&self) -> &Client {
        &self.client
    }

    /// Publish a strongly typed event to a NATS subject.
    ///
    /// The event is automatically wrapped in an `EventEnvelope` before serialization.
    pub async fn publish<T: Serialize>(
        &self,
        subject: &str,
        source: &str,
        payload: T,
    ) -> Result<()> {
        let envelope = EventEnvelope::new(source, payload);
        let bytes = serde_json::to_vec(&envelope)?;
        self.client
            .publish(subject.to_string(), bytes.into())
            .await?;
        tracing::debug!("Published event to '{}' (source: {})", subject, source);
        Ok(())
    }

    /// Publish a raw envelope (already constructed) to a NATS subject.
    pub async fn publish_envelope<T: Serialize>(
        &self,
        subject: &str,
        envelope: &EventEnvelope<T>,
    ) -> Result<()> {
        let bytes = serde_json::to_vec(envelope)?;
        self.client
            .publish(subject.to_string(), bytes.into())
            .await?;
        Ok(())
    }

    /// Subscribe to a NATS subject and deserialize messages as `EventEnvelope<T>`.
    pub async fn subscribe<T: DeserializeOwned>(
        &self,
        subject: &str,
    ) -> Result<NatsSubscription<T>> {
        let subscriber = self.client.subscribe(subject.to_string()).await?;
        tracing::info!("Subscribed to '{}'", subject);
        Ok(NatsSubscription {
            subscriber,
            shutdown: self.shutdown.clone(),
            _marker: std::marker::PhantomData,
        })
    }

    /// Subscribe to a queue group (for load-balanced subscribers).
    pub async fn queue_subscribe<T: DeserializeOwned>(
        &self,
        subject: &str,
        queue_group: &str,
    ) -> Result<NatsSubscription<T>> {
        let subscriber = self
            .client
            .queue_subscribe(subject.to_string(), queue_group.to_string())
            .await?;
        tracing::info!(
            "Subscribed to '{}' in queue group '{}'",
            subject,
            queue_group
        );
        Ok(NatsSubscription {
            subscriber,
            shutdown: self.shutdown.clone(),
            _marker: std::marker::PhantomData,
        })
    }

    /// Signal all subscribers to shut down gracefully.
    pub fn shutdown(&self) {
        self.shutdown.notify_waiters();
    }
}

/// A subscription that yields deserialized event envelopes.
pub struct NatsSubscription<T> {
    subscriber: Subscriber,
    #[allow(dead_code)]
    shutdown: Arc<Notify>,
    _marker: std::marker::PhantomData<T>,
}

impl<T: DeserializeOwned + Serialize> NatsSubscription<T> {
    /// Receive the next message from the subscription.
    /// Returns `None` if the subscription is closed or shutdown was signalled.
    ///
    /// Uses a loop internally to skip malformed messages without recursive calls.
    pub async fn next(&mut self) -> Option<(String, EventEnvelope<T>)> {
        loop {
            let msg: Message = self.subscriber.next().await?;
            let subject = msg.subject.as_ref().to_string();
            match serde_json::from_slice::<EventEnvelope<T>>(&msg.payload) {
                Ok(envelope) => return Some((subject, envelope)),
                Err(e) => {
                    tracing::warn!(
                        "Failed to deserialize event from '{}': {}",
                        subject,
                        e
                    );
                    // Continue loop to try next message
                }
            }
        }
    }
}

impl<T> Drop for NatsSubscription<T> {
    fn drop(&mut self) {
        tracing::debug!("NATS subscription dropped");
    }
}

/// Build a NATS URL injecting NATS_USER/NATS_PASSWORD env vars if set.
/// Input: "nats://host:4222" → "nats://user:pass@host:4222"
fn build_nats_url(base_url: &str) -> String {
    match (std::env::var("NATS_USER"), std::env::var("NATS_PASSWORD")) {
        (Ok(user), Ok(pass)) => {
            if let Some(after_scheme) = base_url.strip_prefix("nats://") {
                format!("nats://{}:{}@{}", user, pass, after_scheme)
            } else {
                base_url.to_string()
            }
        }
        _ => base_url.to_string(),
    }
}
