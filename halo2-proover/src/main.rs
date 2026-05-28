use halo2_proover::Prover;
use std::path::Path;
use std::{env, fs, process};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: halo2-proover <fixture_json_path>");
        process::exit(1);
    }

    let fixture_json = fs::read_to_string(&args[1]).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {}", args[1], e);
        process::exit(1);
    });

    let mut prover = Prover::new(Some(Path::new("."))).unwrap_or_else(|e| {
        eprintln!("Prover init failed: {}", e);
        process::exit(1);
    });

    match prover.generate_proof(&fixture_json) {
        Ok(output) => println!("{}", serde_json::to_string(&output).unwrap()),
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}
