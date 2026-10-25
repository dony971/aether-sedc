use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use crate::transaction::TransactionId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipelineEventKind {
    ReceiverIngress,
    Accepted,
    DrainStart,
    Applied,
}

#[derive(Clone, Debug)]
pub struct PipelineEvent {
    pub label: String,
    pub kind: PipelineEventKind,
    pub tx_id: TransactionId,
    pub at: Instant,
}

#[derive(Debug, Default)]
pub struct PipelineRecorder {
    events: Mutex<Vec<PipelineEvent>>,
}

impl PipelineRecorder {
    pub fn snapshot(&self) -> Vec<PipelineEvent> {
        self.events
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
}

static RECORDER: OnceLock<Mutex<Option<Arc<PipelineRecorder>>>> = OnceLock::new();

fn slot() -> &'static Mutex<Option<Arc<PipelineRecorder>>> {
    RECORDER.get_or_init(|| Mutex::new(None))
}

pub fn install(recorder: Arc<PipelineRecorder>) {
    *slot().lock().unwrap_or_else(|error| error.into_inner()) = Some(recorder);
}

pub fn clear() {
    *slot().lock().unwrap_or_else(|error| error.into_inner()) = None;
}

pub fn record(label: &str, kind: PipelineEventKind, tx_id: TransactionId) {
    let recorder = slot()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    let Some(recorder) = recorder else {
        return;
    };
    if label.is_empty() {
        return;
    }
    recorder
        .events
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .push(PipelineEvent {
            label: label.to_string(),
            kind,
            tx_id,
            at: Instant::now(),
        });
}
