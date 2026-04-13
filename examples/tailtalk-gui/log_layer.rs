use std::sync::mpsc::SyncSender;
use tracing::{Event, Subscriber};
use tracing_subscriber::{layer::Context, Layer};

pub struct GuiLogLayer {
    tx: SyncSender<String>,
}

impl GuiLogLayer {
    pub fn new(tx: SyncSender<String>) -> Self {
        Self { tx }
    }
}

struct MessageExtractor(String);

impl tracing::field::Visit for MessageExtractor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0 = value.to_string();
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

impl<S: Subscriber> Layer<S> for GuiLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = MessageExtractor(String::new());
        event.record(&mut visitor);
        let meta = event.metadata();
        let line = format!("[{}] {}: {}", meta.level(), meta.target(), visitor.0);
        // try_send: never block the server; silently drop if buffer full
        let _ = self.tx.try_send(line);
    }
}
