mod argon2ffi;
mod hash;
mod kdf;
mod verify;
mod wordlist;

use std::fs;
use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::iter::{ParallelBridge, ParallelIterator};

use hash::parse_hash_line;
use kdf::derive_aes_key;
use verify::check_aes_key;
use wordlist::{LineIter, count_lines};

#[derive(Parser)]
#[command(
    name = "sparrow-crack",
    about = "Crack Sparrow Wallet H2 database passwords (Argon2id + secp256k1 + PBKDF2 + XTS)"
)]
struct Cli {
    /// Path to a file containing a $sprw1$ hash, or the hash string itself
    #[arg(short = 'H', long)]
    hash: String,

    /// Wordlist file (omit to read from stdin)
    #[arg(short = 'w', long)]
    wordlist: Option<PathBuf>,

    /// Number of parallel workers (default: number of logical CPUs)
    #[arg(short = 'j', long)]
    jobs: Option<usize>,

    /// Skip the first N candidates — use with pp.save value to resume
    #[arg(long, default_value = "0")]
    skip: u64,

    /// Stop after N candidates (pair with --skip to assign non-overlapping ranges across machines)
    #[arg(long)]
    limit: Option<u64>,

    /// File to save progress line count to every 30 s
    #[arg(long, default_value = ".sparrow-index")]
    progress_file: String,
}

fn main() {
    let args = Cli::parse();

    // --- Parse hash ---
    let hash_line = if args.hash.starts_with('$') {
        args.hash.clone()
    } else {
        fs::read_to_string(&args.hash)
            .unwrap_or_else(|e| {
                eprintln!("Cannot read hash file '{}': {e}", args.hash);
                process::exit(2);
            })
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap_or_default()
            .to_string()
    };
    let hash = parse_hash_line(&hash_line).unwrap_or_else(|e| {
        eprintln!("Hash error: {e}");
        process::exit(2);
    });

    // --- Rayon thread pool ---
    // libargon2 spawns p=4 pthreads internally per call, so cap outer workers at
    // num_cpus/4 to avoid over-subscription (default 4 on a 16-thread machine).
    let jobs = args.jobs.unwrap_or_else(|| (num_cpus::get() / 4).max(1));
    rayon::ThreadPoolBuilder::new()
        .num_threads(jobs)
        .build_global()
        .unwrap();
    eprintln!("Using {jobs} outer worker(s) × 4 libargon2 lanes = {} threads. Memory: {} MB.",
        jobs * 4, jobs * 256);

    // --- Wordlist ---
    let (iter, total) = match &args.wordlist {
        Some(path) => {
            // Only count lines for regular files — stdin/FIFOs would be consumed.
            let total = path.metadata()
                .ok()
                .filter(|m| m.file_type().is_file())
                .and_then(|_| count_lines(path).ok());
            let it = LineIter::from_file(path).unwrap_or_else(|e| {
                eprintln!("Cannot open wordlist '{}': {e}", path.display());
                process::exit(2);
            });
            (it, total)
        }
        None => (LineIter::from_stdin(), None),
    };

    let skip = args.skip;
    let iter = if skip > 0 {
        eprintln!("Skipping {skip} lines (resume mode)...");
        iter.skip_lines(skip)
    } else {
        iter
    };

    // Apply limit (usize::MAX = no limit; Iterator::take is a no-op at that count).
    let limit = args.limit.unwrap_or(u64::MAX) as usize;
    let iter = iter.take(limit);

    // --- Progress bar ---
    let effective_total = total
        .map(|t| t.saturating_sub(skip))
        .map(|t| args.limit.map_or(t, |lim| t.min(lim)));
    let pb = match effective_total {
        Some(t) => {
            let pb = ProgressBar::new(t);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] {wide_bar} {pos}/{len} ({per_sec}) ETA {eta}")
                    .unwrap(),
            );
            pb
        }
        None => {
            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("[{elapsed_precise}] {spinner} {pos} candidates ({per_sec})")
                    .unwrap(),
            );
            pb
        }
    };

    // --- Periodic progress save ---
    // counter tracks attempts made this run; progress file stores absolute index (skip + tried).
    let counter = Arc::new(AtomicU64::new(0));
    {
        let counter = Arc::clone(&counter);
        let save_path = args.progress_file.clone();
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(30));
            let n = counter.load(Ordering::Relaxed);
            let _ = fs::write(&save_path, format!("{}\n", skip + n));
        });
    }

    // --- Crack ---
    let pb_ref = &pb;
    let counter_ref = &counter;
    let hash_ref = &hash;

    let found = iter.par_bridge().find_any(|candidate| {
        pb_ref.inc(1);
        counter_ref.fetch_add(1, Ordering::Relaxed);
        match derive_aes_key(candidate.as_bytes(), hash_ref) {
            Ok(key) => check_aes_key(&key, &hash_ref.ct),
            Err(_) => false,
        }
    });

    pb.finish_and_clear();

    let final_count = counter.load(Ordering::Relaxed);
    let _ = fs::write(&args.progress_file, format!("{}\n", skip + final_count));

    match found {
        Some(pw) => {
            println!("Found: {pw}");
            process::exit(0);
        }
        None => {
            eprintln!("Not found after {final_count} candidates.");
            process::exit(1);
        }
    }
}
