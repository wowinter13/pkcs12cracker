use anyhow::{bail, Result};
use clap::Parser;
use std::path::PathBuf;

/// PKCS#12 password cracker that supports dictionary, pattern-based, and brute force attacks
#[derive(Debug, Parser, Clone)]
#[command(name = "pkcs12cracker")]
#[command(author = "Vladislav Dyachenko")]
#[command(version = "1.0.0")]
#[command(about = "Fast, multi-threaded PKCS#12 password cracker")]
#[command(
    long_about = "Cracks passwords for PKCS#12 files (.p12/.pfx) using multiple attack strategies: \
    dictionary-based, pattern-based, or brute force. Supports multi-threading for faster cracking."
)]
pub struct Args {
    /// Path to the PKCS#12 certificate file to crack
    #[arg(
        required(true),
        num_args(1..),
        value_name = "FILE",
        value_parser = validate_certificate_path,
        help = "Path to the PKCS#12 (.p12/.pfx) file to crack"
    )]
    pub certificate_path: PathBuf,

    /// Path to dictionary file for dictionary-based attack
    #[arg(
        short = 'd',
        long = "dictionary",
        value_name = "FILE",
        help = "Use dictionary-based attack with the specified wordlist file"
    )]
    pub dictionary_path: Option<PathBuf>,

    /// Pattern template for pattern-based attack
    #[arg(
        short = 'p',
        long = "pattern",
        value_name = "PATTERN",
        help = "Use pattern-based attack (e.g., 'Pass@@rd' where '@' marks variable positions)",
        long_help = "Enable pattern-based attack using the specified template. \
                     Variable positions are marked with a symbol (default: '@'). \
                     Example: 'Pass@@rd' will try all combinations replacing '@' positions.",
        conflicts_with_all = ["minumum_length", "maximum_length", "bruteforce_flag"]
    )]
    pub pattern: Option<String>,

    /// Symbol used to mark variable positions in pattern
    #[arg(
        short = 's',
        long = "pattern-symbol",
        value_name = "CHAR",
        default_value = "@",
        help = "Symbol to mark variable positions in pattern [default: @]",
        requires = "pattern",
        conflicts_with_all = ["minumum_length", "maximum_length", "bruteforce_flag"]
    )]
    pub pattern_symbol: char,

    /// Minimum password length for brute force attack
    #[arg(
        short = 'm',
        long = "min-length",
        value_name = "NUM",
        default_value = "1",
        value_parser = clap::value_parser!(u8).range(1..=255),
        help = "Minimum password length for brute force attack [default: 1]",
        requires = "bruteforce_flag",
        conflicts_with_all = ["pattern", "pattern_symbol"]
    )]
    pub minumum_length: u8,

    /// Maximum password length for brute force attack
    #[arg(
        long = "max-length",
        value_name = "NUM",
        default_value = "6",
        value_parser = clap::value_parser!(u8).range(1..=255),
        help = "Maximum password length for brute force attack [default: 6]",
        long_help = "Maximum password length for brute force attack [default: 6]\n\
                     Note: Many PKCS#12 implementations limit passwords to 15 bytes.",
        requires = "bruteforce_flag",
        conflicts_with_all = ["pattern", "pattern_symbol"]
    )]
    pub maximum_length: u8,

    /// Enable brute force attack mode
    #[arg(
        short = 'b',
        long = "brute-force",
        help = "Enable brute force attack mode"
    )]
    pub bruteforce_flag: bool,

    /// Character sets to use in brute force attack
    #[arg(
        short = 'c',
        long = "charset",
        value_name = "SETS",
        help = "Character sets to use in brute force attack",
        long_help = "Specify one or more character sets for password generation:\n\
                     a - lowercase letters (a-z)\n\
                     A - uppercase letters (A-Z)\n\
                     n - digits (0-9)\n\
                     s - special chars (!@#$%^&*...)\n\
                     x - all of the above\n\
                     Example: 'aAn' for alphanumeric passwords"
    )]
    pub char_sets: Option<String>,

    /// Custom character set for brute force attack
    #[arg(
        long = "custom-chars",
        value_name = "CHARS",
        help = "Custom character set for brute force attack",
        long_help = "Define a custom set of characters to use in brute force attack.\n\
                     Example: 'abcABC123!@#'"
    )]
    pub specific_chars: Option<String>,

    /// Delimiter for dictionary entries
    #[arg(
        long = "delimiter",
        value_name = "CHAR",
        default_value = "\n",
        help = "Dictionary file entry delimiter [default: newline]",
        requires = "pattern"
    )]
    pub delimiter: String,

    /// Number of threads to use
    #[arg(
        short = 't',
        long = "threads",
        value_name = "NUM",
        value_parser = validate_threads_count,
        default_value = "1",
        help = "Number of cracking threads [default: number of CPU cores]"
    )]
    pub threads: u8,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            char_sets: None,
            specific_chars: None,
            certificate_path: PathBuf::new(),
            dictionary_path: None,
            pattern: None,
            pattern_symbol: '@',
            minumum_length: 1,
            maximum_length: 8,
            bruteforce_flag: false,
            delimiter: String::new(),
            threads: 1,
        }
    }
}

fn validate_threads_count(threads: &str) -> Result<u8> {
    let threads = threads.parse::<u8>()?;
    if threads > 1 {
        Ok(threads)
    } else {
        Ok(num_cpus::get() as u8)
    }
}

fn validate_certificate_path(path: &str) -> Result<PathBuf> {
    let path = PathBuf::from(path);
    if path.extension().is_some() {
        Ok(path)
    } else {
        bail!("Certificate file must have .p12 or .pfx extension");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_certificate_path() {
        let path = String::from("test.p12");
        assert!(validate_certificate_path(&path).is_ok());
    }

    #[test]
    fn test_validate_certificate_path_invalid() {
        let path = String::from("test");
        assert!(validate_certificate_path(&path).is_err());
    }
}
