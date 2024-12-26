//! Pattern-based password cracking implementation.
//!
//! This module provides functionality for cracking passwords using a pattern
//! where some positions are fixed and others are variable. For example,
//! "Pass@@rd" would try all combinations replacing @ symbols.
use crate::types::{CrackResult, PasswordCracker};
use anyhow::Result;
use openssl::pkcs12::Pkcs12;
use rayon::prelude::*;
use std::sync::{Arc, Mutex};

/// Implements pattern-based password cracking.
///
/// Uses a template pattern where certain positions are fixed and others
/// are tried with all possible characters from the charset.
pub struct PatternCracker {
    /// Template pattern (e.g., "Pass@@rd")
    pattern: String,
    /// Characters to try in variable positions
    charset: String,
    /// Characters to try in variable positions
    pattern_symbol: char,
}

impl PatternCracker {
    /// Creates a new PatternCracker instance.
    ///
    /// # Arguments
    ///
    /// * `pattern` - Template pattern with fixed and variable positions
    /// * `charset` - Characters to try in variable positions
    /// * `pattern_symbol` - Symbol marking variable positions (e.g., '@')
    pub fn new(pattern: String, charset: String, pattern_symbol: char) -> Self {
        Self {
            pattern,
            charset,
            pattern_symbol,
        }
    }

    /// Processes a chunk of pattern combinations.
    ///
    /// # Arguments
    ///
    /// * `chunk` - Bytes from the memory-mapped file
    /// * `pattern` - The template pattern
    /// * `unknown_positions` - Indices of variable positions in the pattern
    /// * `pkcs12` - The PKCS#12 certificate to crack
    /// * `result` - Shared result tracking structure
    #[inline(always)]
    fn process_chunk(
        chunk: &[String],
        pattern: &str,
        unknown_positions: &[usize],
        pkcs12: &Pkcs12,
        result: &Arc<Mutex<CrackResult>>,
    ) -> bool {
        let mut password_chars = Vec::with_capacity(pattern.len());

        for combination in chunk {
            {
                let result_guard = result.lock().unwrap();
                if result_guard.password.is_some() {
                    return true;
                }
                result_guard.increment_attempts();
            }

            password_chars.clear();
            password_chars.extend(pattern.chars());

            for (pos, c) in unknown_positions.iter().zip(combination.chars()) {
                password_chars[*pos] = c;
            }

            let password: String = password_chars.iter().collect();
            if super::check_password(pkcs12, &password, result) {
                return true;
            }
        }
        false
    }

    /// Generates combinations for variable positions in the pattern.
    ///
    /// Similar to the main combination generator, but specifically for
    /// filling in the variable positions in the pattern.
    ///
    /// # Arguments
    ///
    /// * `charset` - Characters to use in combinations
    /// * `length` - Number of positions to fill
    /// * `current` - Current combination being built
    /// * `result` - Vector to store generated combinations
    fn generate_pattern_combinations(
        charset: &[char],
        length: u8,
        current: &String,
        result: &mut Vec<String>,
    ) {
        if length == 0 {
            result.push(current.clone());
            return;
        }

        let mut new_str = current.clone();
        for &c in charset {
            new_str.push(c);
            Self::generate_pattern_combinations(charset, length - 1, &new_str, result);
            new_str.pop();
        }
    }
}

impl PasswordCracker for PatternCracker {
    /// Attempts to crack the PKCS#12 password using pattern-based approach.
    ///
    /// # Performance
    ///
    /// The time complexity is O(n^v) where:
    /// - n is the size of the character set
    /// - v is the number of variable positions in the pattern
    ///
    /// This is generally much more efficient than pure brute force when
    /// parts of the password are known.
    fn crack(&self, pkcs12: &Arc<Pkcs12>, result: &Arc<Mutex<CrackResult>>) -> Result<()> {
        let mut password = String::with_capacity(self.pattern.len());
        let mut unknown_positions = Vec::with_capacity(self.pattern.len());

        // Pre-process pattern
        for (i, c) in self.pattern.chars().enumerate() {
            if c == self.pattern_symbol {
                unknown_positions.push(i);
                password.push('?');
            } else {
                password.push(c);
            }
        }

        let charset: Vec<char> = self.charset.chars().collect();
        let mut combinations = Vec::new();

        println!(
            "Generating pattern combinations for {} unknown positions",
            unknown_positions.len()
        );
        Self::generate_pattern_combinations(
            &charset,
            unknown_positions.len() as u8,
            &String::new(),
            &mut combinations,
        );

        combinations
            .par_chunks(super::CHUNK_SIZE)
            .find_any(|chunk| {
                Self::process_chunk(chunk, &password, &unknown_positions, pkcs12, result)
            });

        Ok(())
    }
}
