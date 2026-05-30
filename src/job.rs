//! Background, multi-core mnemonic generation so the UI thread never blocks.
//!
//! A coordinator thread splits the requested count into contiguous chunks and
//! hands each to a worker thread (one per available CPU). Workers report
//! progress through a shared atomic counter and honour a shared cancel flag.
//! The assembled text is sent back to the UI over a channel; the UI polls it
//! each frame with [`RunningJob::try_take`].

use std::fmt::Write as _;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::thread;

use bip39::Mnemonic;

use crate::derive;
use crate::generate_one;

/// Worker flushes its local progress counter to the shared one this often,
/// to keep cross-thread atomic contention negligible.
const PROGRESS_BATCH: usize = 256;

/// Handle to an in-flight generation job, owned by the UI.
pub struct RunningJob {
    pub total: usize,
    done: Arc<AtomicUsize>,
    cancel: Arc<AtomicBool>,
    rx: Receiver<JobResult>,
}

pub struct JobResult {
    pub text: String,
    pub produced: usize,
    pub cancelled: bool,
}

impl RunningJob {
    /// Mnemonics completed so far (across all workers).
    pub fn done(&self) -> usize {
        self.done.load(Ordering::Relaxed)
    }

    /// Ask the workers to stop as soon as they notice.
    pub fn request_cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    /// Non-blocking: `Some(result)` once the job has finished.
    pub fn try_take(&self) -> Option<JobResult> {
        self.rx.try_recv().ok()
    }
}

/// Spawn a job and return immediately. Nothing runs on the caller's thread.
pub fn start(count: usize, words: usize, derive_addrs: bool) -> RunningJob {
    let done = Arc::new(AtomicUsize::new(0));
    let cancel = Arc::new(AtomicBool::new(false));
    let (tx, rx) = channel();

    let done_coord = Arc::clone(&done);
    let cancel_coord = Arc::clone(&cancel);

    thread::spawn(move || {
        let n_threads = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .clamp(1, count.max(1));

        let base = count / n_threads;
        let remainder = count % n_threads;

        let mut handles = Vec::with_capacity(n_threads);
        let mut start_idx = 0usize;
        for t in 0..n_threads {
            // Spread the remainder across the first chunks so sizes differ by ≤1.
            let len = base + if t < remainder { 1 } else { 0 };
            if len == 0 {
                continue;
            }
            let range = start_idx..start_idx + len;
            start_idx += len;
            let done_w = Arc::clone(&done_coord);
            let cancel_w = Arc::clone(&cancel_coord);
            handles.push(thread::spawn(move || {
                produce_chunk(range, words, derive_addrs, &done_w, &cancel_w)
            }));
        }

        // Concatenate chunks in index order; drop each as we go to cap memory.
        let mut text = String::new();
        let mut produced = 0usize;
        for handle in handles {
            if let Ok((chunk, n)) = handle.join() {
                text.push_str(&chunk);
                produced += n;
            }
        }

        let cancelled = cancel_coord.load(Ordering::Relaxed);
        let _ = tx.send(JobResult { text, produced, cancelled });
    });

    RunningJob { total: count, done, cancel, rx }
}

/// Generate one contiguous range of mnemonics into a single String.
fn produce_chunk(
    range: Range<usize>,
    words: usize,
    derive_addrs: bool,
    done: &AtomicUsize,
    cancel: &AtomicBool,
) -> (String, usize) {
    let mut out = String::new();
    let mut produced = 0usize;
    let mut local = 0usize;

    for idx in range {
        if cancel.load(Ordering::Relaxed) {
            break;
        }

        let phrase = match generate_one(words) {
            Ok(p) => p,
            Err(_) => break,
        };

        if derive_addrs {
            match Mnemonic::parse(&phrase)
                .map_err(|e| e.to_string())
                .and_then(|m| derive::addresses_for(&m))
            {
                Ok(a) => {
                    let _ = write!(
                        out,
                        "#{}  {phrase}\n    BTC  {}\n    ETH  {}\n    TRX  {}\n    SOL  {}\n    SUI  {}\n\n",
                        idx + 1,
                        a.btc,
                        a.eth,
                        a.trx,
                        a.sol,
                        a.sui
                    );
                }
                Err(_) => break,
            }
        } else {
            out.push_str(&phrase);
            out.push('\n');
        }

        produced += 1;
        local += 1;
        if local >= PROGRESS_BATCH {
            done.fetch_add(local, Ordering::Relaxed);
            local = 0;
        }
    }

    if local > 0 {
        done.fetch_add(local, Ordering::Relaxed);
    }
    (out, produced)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_exact_count() {
        let job = start(1000, 12, false);
        let result = job.rx.recv().expect("job result");
        assert!(!result.cancelled);
        assert_eq!(result.produced, 1000);
        assert_eq!(result.text.lines().count(), 1000);
        assert_eq!(job.done(), 1000);
        for line in result.text.lines() {
            assert_eq!(line.split_whitespace().count(), 12);
        }
    }

    // Rough speedup check; run with:
    //   cargo test --release bench_derive -- --ignored --nocapture
    #[test]
    #[ignore]
    fn bench_derive() {
        use std::time::Instant;
        let n = 4000usize;

        let t0 = Instant::now();
        for _ in 0..n {
            let phrase = generate_one(12).unwrap();
            let m = Mnemonic::parse(&phrase).unwrap();
            let _ = derive::addresses_for(&m).unwrap();
        }
        let serial = t0.elapsed();

        let t1 = Instant::now();
        let r = start(n, 12, true).rx.recv().unwrap();
        let parallel = t1.elapsed();

        let cores = thread::available_parallelism().map(|c| c.get()).unwrap_or(0);
        eprintln!("cores              : {cores}");
        eprintln!(
            "serial (derive x{n}) : {serial:?}  ({:.0}/s)",
            n as f64 / serial.as_secs_f64()
        );
        eprintln!(
            "parallel job        : {parallel:?}  ({:.0}/s)",
            r.produced as f64 / parallel.as_secs_f64()
        );
        eprintln!(
            "speedup             : {:.1}x",
            serial.as_secs_f64() / parallel.as_secs_f64()
        );
    }

    // Output must stay globally ordered even though chunks run on separate
    // threads (chunk N covers a contiguous, higher index range than chunk N-1).
    #[test]
    fn stays_ordered_across_chunks_when_deriving() {
        let job = start(50, 12, true);
        let result = job.rx.recv().expect("job result");
        assert_eq!(result.produced, 50);
        let headers: Vec<&str> = result.text.lines().filter(|l| l.starts_with('#')).collect();
        assert_eq!(headers.len(), 50);
        assert!(headers[0].starts_with("#1  "), "first: {}", headers[0]);
        assert!(headers[49].starts_with("#50  "), "last: {}", headers[49]);
    }
}
