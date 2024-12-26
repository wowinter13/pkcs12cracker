//! Dictionary-based password cracking implementation.
//!
//! This module provides functionality for cracking PKCS#12 passwords
//! using a dictionary file with memory-mapped parallel processing.
use crate::types::{CrackResult, PasswordCracker};
use anyhow::{Context, Result};
use memmap2::Mmap;
use openssl::pkcs12::Pkcs12;
use rayon::prelude::*;
use std::fs::File;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Implements dictionary-based password cracking.
///
/// Uses memory mapping and parallel processing to efficiently test passwords.
pub struct DictionaryCracker {
    /// Path to the dictionary file
    dictionary_path: PathBuf,
    /// Delimiter used to separate entries in the dictionary file
    delimiter: String,
}

impl DictionaryCracker {
    /// Creates a new DictionaryCracker instance.
    ///
    /// # Arguments
    ///
    /// * `dictionary_path` - Path to the dictionary file
    /// * `delimiter` - Character used to separate entries in the file
    pub fn new(dictionary_path: PathBuf, delimiter: String) -> Self {
        Self {
            dictionary_path,
            delimiter,
        }
    }

    /// Processes a chunk of the dictionary file.
    ///
    /// # Safety(!)
    ///
    /// Assumes the chunk is valid UTF-8. Invalid UTF-8 sequences are skipped.
    ///
    /// # Arguments
    ///
    /// * `chunk` - Bytes from the memory-mapped file
    /// * `delimiter` - Character separating passwords in the file
    /// * `pkcs12` - The PKCS#12 certificate to crack
    /// * `result` - Shared result tracking structure
    #[inline(always)]
    fn process_chunk(
        chunk: &[u8],
        delimiter: char,
        pkcs12: &Pkcs12,
        result: &Arc<Mutex<CrackResult>>,
    ) -> bool {
        if let Ok(text) = std::str::from_utf8(chunk) {
            for line in text.split(delimiter) {
                {
                    let result_guard = result.lock().unwrap();
                    if result_guard.password.is_some() {
                        return true;
                    }
                    result_guard.increment_attempts();
                }

                let password = line.trim().to_string();
                if super::check_password(pkcs12, &password, result) {
                    return true;
                }
            }
        }
        false
    }
}

impl PasswordCracker for DictionaryCracker {
    /// Attempts to crack the PKCS#12 password using the dictionary file.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The dictionary file cannot be opened or read
    /// - Memory mapping fails
    fn crack(&self, pkcs12: &Arc<Pkcs12>, result: &Arc<Mutex<CrackResult>>) -> Result<()> {
        println!(
            "Starting dictionary attack with {} threads",
            rayon::current_num_threads()
        );

        let dict_file =
            File::open(&self.dictionary_path).context("Failed to open dictionary file")?;

        let mmap = unsafe { Mmap::map(&dict_file)? };
        let delimiter = self.delimiter.as_bytes()[0] as char;

        mmap.par_chunks(super::CHUNK_SIZE)
            .find_any(|chunk| Self::process_chunk(chunk, delimiter, pkcs12, result));

        Ok(())
    }
}
