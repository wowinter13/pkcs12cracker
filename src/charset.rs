//! Charset utilities.
//!
//! This module provides predefined character sets and functionality to build
//! custom character sets for password cracking.
//!
use crate::args::Args;
use anyhow::Result;

/// Lowercase letters from a to z
pub static LOWER_ALPHABET: &str = "abcdefghijklmnopqrstuvwxyz";
/// Uppercase letters from A to Z
pub static UPPER_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// Digits from 0 to 9
pub static DIGITS: &str = "0123456789";
/// Common special characters used in passwords
pub static SPECIAL_CHARS: &str = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ ";

/// Builds a character set based on provided arguments.
///
/// # Arguments
///
/// * `args` - CLI arguments containing charset configuration
///
/// # Returns
///
/// Returns a `Result` containing the constructed character set string.
///
/// # Example
///
/// ```no_run
/// use pkcs12cracker::Args;
/// let args = Args {
///     char_sets: Some("aA".to_string()), // lowercase and uppercase
///     specific_chars: Some("@#".to_string()), // additional chars
///     ..Default::default()
/// };
/// let charset = build_charset(&args).unwrap();
/// ```
#[inline(always)]
pub fn build_charset(args: &Args) -> Result<String> {
    let mut charset = if let Some(char_sets) = &args.char_sets {
        let mut chars = String::with_capacity(128);
        for c in char_sets.chars() {
            match c {
                'a' => chars.push_str(LOWER_ALPHABET),
                'A' => chars.push_str(UPPER_ALPHABET),
                'n' => chars.push_str(DIGITS),
                's' => chars.push_str(SPECIAL_CHARS),
                'x' => {
                    chars.push_str(LOWER_ALPHABET);
                    chars.push_str(UPPER_ALPHABET);
                    chars.push_str(DIGITS);
                    chars.push_str(SPECIAL_CHARS);
                }
                _ => (),
            }
        }
        chars
    } else {
        LOWER_ALPHABET.to_string()
    };

    if let Some(specific_chars) = &args.specific_chars {
        charset.push_str(specific_chars);
    }

    Ok(charset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::Args;

    #[test]
    fn test_build_charset() {
        let args = Args {
            char_sets: Some("aA".to_string()),
            specific_chars: Some("@#".to_string()),
            ..Default::default()
        };
        let charset = build_charset(&args).unwrap();
        assert_eq!(
            charset,
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@#"
        );
    }

    #[test]
    fn test_build_charset_default() {
        let args = Args::default();
        let charset = build_charset(&args).unwrap();
        assert_eq!(charset, LOWER_ALPHABET);
    }

    #[test]
    fn test_build_charset_specific_chars() {
        let args = Args {
            specific_chars: Some("@#".to_string()),
            ..Default::default()
        };
        let charset = build_charset(&args).unwrap();
        assert!(charset.contains("@"));
        assert!(charset.contains("#"));
    }

    #[test]
    fn test_build_charset_all() {
        let args = Args {
            char_sets: Some("x".to_string()),
            ..Default::default()
        };
        let charset = build_charset(&args).unwrap();
        assert_eq!(charset, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ ");
    }

    #[test]
    fn test_build_charset_with_umlauts() {
        let args = Args {
            char_sets: Some("aA".to_string()),
            specific_chars: Some("äöüß".to_string()),
            ..Default::default()
        };
        let charset = build_charset(&args).unwrap();
        assert_eq!(
            charset,
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZäöüß"
        );
    }
}
