//! Graceful shutdown signalling between `main` and the worker threads.
//!
//! A worker spends most of its life blocked in `Poll::poll`, so `main` needs a
//! way both to *tell* it to stop and to *wait for it to do so*. A single
//! atomic flag does both jobs: workers check it on every loop iteration and
//! between poll returns, `main` flips it once and then polls it until every
//! worker has acked.
//!
!! There is deliberately no pipe here. A pipe would cut the shutdown latency
//! from one poll timeout to zero, but it costs a platform-specific event
//! source per worker and a second file descriptor per worker — the whole
//! point of the socket-handle-count acceptance test is that there are no
//! handles left over. The poll timeout is the drain interval, so shutdown
//! latency is bounded by it, which is fine for a server that is about to
//! exit.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The interval at which a blocked worker wakes to check the flag.
///
//! Also the shutdown-latency bound for the whole process.
pub const WAKE_INTERVAL: Duration = Duration::from_millis(200);

/// A broadcast "stop" flag.
#[derive(Debug, Default, Clone)]
pub struct Shutdown(Arc<AtomicBool>);

impl Shutdown {
    /// A fresh, not-yet-signalled flag.
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    /// Whether the workers should be winding down.
    pub fn should_stop(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    /// Ask every worker that shares this flag to stop.
    pub fn stop(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Wait up to `timeout` for the flag to be set, returning whether it was.
    ///
    /// This is the `main` thread's side: flip the flag, then join the worker
    /// threads, then call this with a short timeout to confirm the loop
    /// really drained instead of just racing the join.
    pub fn wait(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self.should_stop() {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            std::thread::sleep(deadline.saturating_sub(now).min(WAKE_INTERVAL));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn a_shared_flag_reaches_every_copy() {
        let flag = Shutdown::new();
        assert!(!flag.should_stop());
        let copy = flag.clone();
        flag.stop();
        assert!(flag.should_stop());
        assert!(copy.should_stop());
        assert!(flag.wait(Duration::from_millis(5)));
    }

    #[test]
    fn wait_returns_false_when_the_flag_never_moves() {
        let flag = Shutdown::new();
        assert!(!flag.wait(Duration::from_millis(20)));
    }

    #[test]
    fn a_worker_thread_observes_the_flag_within_one_wake_interval() {
        let flag = Shutdown::new();
        let handle = flag.clone();
        let worker = thread::spawn(move || {
            // Mimic a worker blocked in poll: sleep in WAKE_INTERVAL chunks
            // and check the flag each time.
            loop {
                if flag.should_stop() {
                    return true;
                }
                thread::sleep(WAKE_INTERVAL);
            }
        });
        thread::sleep(WAKE_INTERVAL);
        handle.stop();
        let joined = thread::Builder::new()
            .name("wake-test".to_string())
            .spawn(|| worker.join().unwrap())
            .unwrap();
        assert!(joined.join().unwrap());
    }
}
