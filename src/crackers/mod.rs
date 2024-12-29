//! Password cracking strategies and utilities.
pub mod bruteforce;
pub mod dictionary;
pub mod pattern;

use openssl::pkcs12::Pkcs12;
use std::sync::{Arc, Mutex};

/// Optimal chunk size for parallel processing, tuned for modern CPU cache sizes.
/// 16KB is chosen as a compromise between cache efficiency and parallelism.
const CHUNK_SIZE: usize = 16384;

/// Attempts to decrypt a PKCS#12 certificate with a given password.
///
/// This function is used internally by all cracking strategies.
///
/// # Arguments
///
/// * `pkcs12` - The PKCS#12 certificate to test
/// * `password` - The password to try
/// * `result` - Shared result object to store the password if successful
///
/// # Returns
///
/// Returns `true` if the password was correct, `false` otherwise.
#[inline(always)]
pub(crate) fn check_password(
    pkcs12: &Pkcs12,
    password: &str,
    result: &Arc<Mutex<crate::types::CrackResult>>,
) -> bool {
    match pkcs12.parse2(password) {
        Ok(_) => {
            let mut result_guard = result.lock().unwrap();
            result_guard.password = Some(password.to_string());
            println!("\nFound correct password: {password}");
            true
        }
        Err(_) => false,
    }
}

/// Recursively generates all possible combinations of characters.
///
/// Used by bruteforce and pattern-based cracking strategies to generate
/// password candidates.
///
/// # Arguments
///
/// * `charset` - Set of characters to use for combinations
/// * `length` - Length of combinations to generate
/// * `current` - Current combination being built
/// * `result` - Vector to store generated combinations
///
/// # Example
///
/// ```no_run
/// let mut combinations = Vec::new();
/// let charset = vec!['a', 'b', 'c'];
/// generate_combinations(&charset, 2, &String::new(), &mut combinations);
/// // combinations will contain: ["aa", "ab", "ac", "ba", "bb", "bc", "ca", "cb", "cc"]
/// ```
pub(crate) fn generate_combinations(
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
        generate_combinations(charset, length - 1, &new_str, result);
        new_str.pop();
    }
}
