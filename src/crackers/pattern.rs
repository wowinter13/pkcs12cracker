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
        current: &str,
        result: &mut Vec<String>,
    ) {
        if length == 0 {
            result.push(current.to_owned());
            return;
        }

        let mut new_str = current.to_owned();
        for &c in charset {
            new_str.push(c);
            Self::generate_pattern_combinations(charset, length - 1, &new_str, result);
            new_str.pop();
        }
    }

    /// Generates chunks of combinations for large pattern sizes to avoid memory issues
    /// and improve parallelism.
    ///
    /// # Arguments
    ///
    /// * `charset` - Characters to use in combinations
    /// * `unknown_positions` - Number of unknown positions
    /// * `chunk_size` - Size of each chunk
    /// * `pkcs12` - The PKCS#12 certificate to crack
    /// * `result` - Shared result tracking structure
    /// * `pattern` - The template pattern
    /// * `positions` - Indices of variable positions in the pattern
    ///
    /// # Returns
    ///
    /// Returns `true` if the password was found, `false` otherwise.
    fn process_chunks_in_parallel(
        charset: &[char],
        unknown_count: usize,
        chunk_size: usize,
        pkcs12: &Arc<Pkcs12>,
        result: &Arc<Mutex<CrackResult>>,
        pattern: &str,
        positions: &[usize],
    ) -> bool {
        let charset_len = charset.len();
        let mut total_combinations: usize = 1;
        for _ in 0..unknown_count {
            // Overflow protection for very large combination spaces
            if total_combinations > usize::MAX / charset_len {
                total_combinations = usize::MAX / 2;
                break;
            }
            total_combinations *= charset_len;
        }

        let adjusted_chunk_size = if unknown_count > 4 {
            charset_len.pow(3)
        } else {
            chunk_size
        };

        println!(
            "Processing {} combinations in chunks of ~{}",
            total_combinations, adjusted_chunk_size
        );

        // We'll use position indices to iterate through the combination space
        // The "position indices" approach allows us to process combinations
        // without generating them all at once

        let num_chunks = (total_combinations + adjusted_chunk_size - 1) / adjusted_chunk_size;
        let chunks_range = 0..num_chunks;

        // Use Rayon for parallel processing of chunks
        chunks_range
            .into_par_iter()
            .find_any(|chunk_idx| {
                let start_idx = chunk_idx * adjusted_chunk_size;
                let end_idx = (start_idx + adjusted_chunk_size).min(total_combinations);

                // Generate just this chunk of combinations
                let mut chunk_combinations = Vec::with_capacity(end_idx - start_idx);
                for combo_idx in start_idx..end_idx {
                    // Convert the linear index to a combination
                    let mut indices = Vec::with_capacity(unknown_count);
                    let mut remaining = combo_idx;

                    for _ in 0..unknown_count {
                        indices.push(remaining % charset_len);
                        remaining /= charset_len;
                    }

                    // Generate the actual combination string
                    let combination: String = indices.into_iter().map(|idx| charset[idx]).collect();

                    chunk_combinations.push(combination);
                }

                Self::process_chunk(&chunk_combinations, pattern, positions, pkcs12, result)
            })
            .is_some()
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
        let unknown_count = unknown_positions.len();

        println!(
            "Generating pattern combinations for {} unknown positions",
            unknown_count
        );

        let found = if unknown_count >= 4 {
            Self::process_chunks_in_parallel(
                &charset,
                unknown_count,
                super::CHUNK_SIZE,
                pkcs12,
                result,
                &password,
                &unknown_positions,
            )
        } else {
            let mut combinations = Vec::new();
            Self::generate_pattern_combinations(
                &charset,
                unknown_count as u8,
                "",
                &mut combinations,
            );

            combinations
                .par_chunks(super::CHUNK_SIZE)
                .find_any(|chunk| {
                    Self::process_chunk(chunk, &password, &unknown_positions, pkcs12, result)
                })
                .is_some()
        };

        if !found {
            println!("All combinations exhausted, password not found");
        }

        Ok(())
    }
}
