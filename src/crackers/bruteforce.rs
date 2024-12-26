//! Brute force password cracking implementation.
//!
//! This module provides functionality for testing all possible combinations
//! within a given charset and length range.
use crate::types::{CrackResult, PasswordCracker};
use anyhow::Result;
use openssl::pkcs12::Pkcs12;
use rayon::prelude::*;
use std::sync::{Arc, Mutex};

/// Implements brute force password cracking.
pub struct BruteforceCracker {
    /// Minimum password length to try
    min_len: u8,
    /// Maximum password length to try
    max_len: u8,
    /// String containing all characters to use in combinations
    charset: String,
}

impl BruteforceCracker {
    /// Creates a new BruteforceCracker instance.
    ///
    /// # Arguments
    ///
    /// * `min_len` - Minimum password length to test
    /// * `max_len` - Maximum password length to test
    /// * `charset` - String containing all characters to use in combinations
    pub fn new(min_len: u8, max_len: u8, charset: String) -> Self {
        Self {
            min_len,
            max_len,
            charset,
        }
    }

    /// Processes a chunk of generated password combinations.
    ///
    /// # Arguments
    ///
    /// * `chunk` - Bytes from the memory-mapped file
    /// * `pkcs12` - The PKCS#12 certificate to crack
    /// * `result` - Shared result tracking structure
    ///
    /// # Returns
    ///
    /// Returns `true` if the correct password is found in this chunk.
    fn process_chunk(chunk: &[String], pkcs12: &Pkcs12, result: &Arc<Mutex<CrackResult>>) -> bool {
        for password in chunk {
            {
                let result_guard = result.lock().unwrap();
                if result_guard.password.is_some() {
                    return true;
                }
                result_guard.increment_attempts();
            }

            if super::check_password(pkcs12, password, result) {
                return true;
            }
        }
        false
    }
}

impl PasswordCracker for BruteforceCracker {
    /// Attempts to crack the PKCS#12 password using brute force.
    ///
    /// Generates all possible password combinations within the specified length range
    /// and character set, testing them in parallel.
    ///
    /// # Performance(!)
    ///
    /// The time complexity is O(n^l) where:
    /// - n is the size of the character set
    /// - l is the password length
    ///
    /// Memory usage grows with the number of combinations being tested in parallel.
    fn crack(&self, pkcs12: &Arc<Pkcs12>, result: &Arc<Mutex<CrackResult>>) -> Result<()> {
        println!(
            "Generating passwords with length between {} and {}",
            self.min_len, self.max_len
        );
        let charset: Vec<char> = self.charset.chars().collect();
        println!("Charset: {:?}", charset);

        for len in self.min_len..=self.max_len {
            let mut combinations = Vec::new();
            super::generate_combinations(
                &charset,
                len,
                &String::with_capacity(len as usize),
                &mut combinations,
            );

            if combinations
                .par_chunks(super::CHUNK_SIZE)
                .find_any(|chunk| Self::process_chunk(chunk, pkcs12, result))
                .is_some()
            {
                break;
            }
        }

        Ok(())
    }
}
