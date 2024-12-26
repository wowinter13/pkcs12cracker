mod args;
mod charset;
mod crackers;
mod types;

use anyhow::{Context, Result};
use clap::Parser;
use crackers::{
    bruteforce::BruteforceCracker, dictionary::DictionaryCracker, pattern::PatternCracker,
};
use openssl::pkcs12::Pkcs12;
use rayon::ThreadPoolBuilder;
use std::fs::File;
use std::io::Read;
use std::sync::{Arc, Mutex};
use types::{CrackResult, PasswordCracker};

/// Typical size of a PKCS#12 certificate file for buffer pre-allocation
const TYPICAL_PKCS12_SIZE: usize = 4096;

fn main() {
    let args = args::Args::parse();
    let result = run(args);

    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

/// Main execution logic for the password cracker.
///
/// Initializes the thread pool, loads the certificate, and executes
/// the appropriate cracking strategy based on command line arguments.
///
/// # Errors
///
/// Returns an error if:
/// - Thread pool initialization fails
/// - Certificate loading fails
/// - No cracking mode is specified
/// - The selected cracking strategy fails
fn run(args: args::Args) -> Result<()> {
    setup_thread_pool(&args)?;
    let pkcs12 = load_certificate(&args)?;
    let result = Arc::new(Mutex::new(CrackResult::new()));

    let cracker: Box<dyn PasswordCracker> = if let Some(pattern) = args.pattern.as_ref() {
        let charset = charset::build_charset(&args)?;
        Box::new(PatternCracker::new(
            pattern.clone(),
            charset,
            args.pattern_symbol,
        ))
    } else if args.bruteforce_flag {
        let charset = charset::build_charset(&args)?;
        Box::new(BruteforceCracker::new(
            args.minumum_length,
            args.maximum_length,
            charset,
        ))
    } else if let Some(dict_path) = args.dictionary_path {
        Box::new(DictionaryCracker::new(dict_path, args.delimiter))
    } else {
        return Err(anyhow::anyhow!(
            "No cracking mode specified. Use --pattern, --brute-force, or --dictionary"
        ));
    };

    println!("Starting password cracking...");
    cracker.crack(&pkcs12, &result)?;

    let final_result = result.lock().unwrap();
    match &final_result.password {
        Some(password) => println!("Successfully found password: {password}"),
        None => println!("Password not found"),
    }
    println!("Total attempts: {}", final_result.get_attempts());

    Ok(())
}

/// Initializes the global thread pool for parallel processing.
///
/// # Arguments
///
/// * `args` - Command line arguments containing thread count
///
/// # Errors
///
/// Returns an error if thread pool initialization fails
fn setup_thread_pool(args: &args::Args) -> Result<()> {
    ThreadPoolBuilder::new()
        .num_threads(args.threads as usize)
        .build_global()
        .context("Failed to build thread pool")
}

/// Loads and parses a PKCS#12 certificate from file.
///
/// # Arguments
///
/// * `args` - Command line arguments containing certificate path
///
/// # Errors
///
/// Returns an error if:
/// - The certificate file cannot be opened
/// - The file cannot be read
/// - The PKCS#12 data is invalid
fn load_certificate(args: &args::Args) -> Result<Arc<Pkcs12>> {
    let mut cert_file = File::open(&args.certificate_path).with_context(|| {
        format!(
            "Failed to open certificate file: {}",
            args.certificate_path.display()
        )
    })?;

    let mut cert_data = Vec::with_capacity(TYPICAL_PKCS12_SIZE);
    cert_file
        .read_to_end(&mut cert_data)
        .context("Failed to read certificate data")?;

    Ok(Arc::new(
        Pkcs12::from_der(&cert_data).context("Failed to parse PKCS12 data")?,
    ))
}
