//! Core types for password cracking operations.
//!
use anyhow::Result;
use openssl::pkcs12::Pkcs12;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Represents the result of a password cracking attempt.
///
/// Thread-safe structure that holds the discovered password (if exists)
/// and tracks the number of attempts made.
pub struct CrackResult {
    pub password: Option<String>,
    attempts: AtomicUsize,
}

impl CrackResult {
    /// Creates a new `CrackResult` instance.
    pub fn new() -> Self {
        Self {
            password: None,
            attempts: AtomicUsize::new(0),
        }
    }

    /// Increments the attempt counter atomically.
    ///
    /// As exact count is not important, we use relaxed ordering.
    #[inline(always)]
    pub fn increment_attempts(&self) {
        self.attempts.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the current number of password attempts.
    pub fn get_attempts(&self) -> usize {
        self.attempts.load(Ordering::Relaxed)
    }
}

/// The interface for password cracking implementations.
///
/// This trait must be implemented by all password cracking strategies.
pub trait PasswordCracker {
    /// Attempts to crack the provided PKCS#12 certificate.
    fn crack(&self, pkcs12: &Arc<Pkcs12>, result: &Arc<Mutex<CrackResult>>) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn test_crack_result() {
        let result = CrackResult::new();
        result.increment_attempts();
        assert_eq!(result.get_attempts(), 1);
    }

    #[test]
    fn test_crack_result_multi_threaded() {
        let result = Arc::new(Mutex::new(CrackResult::new()));
        let mut handles = vec![];
        for _ in 0..100 {
            let result = result.clone();
            handles.push(thread::spawn(move || {
                result.lock().unwrap().increment_attempts();
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(result.lock().unwrap().get_attempts(), 100);
    }
}
