use ark_serialize::CanonicalSerialize;
use ark_utils::evm::groth16_verifier_solidity::SolidityContractGenerator;
use clap::Parser;
use std::{
    collections::HashMap,
    fs::File,
    io::{Cursor, Write},
};

#[derive(Parser)]
#[command(about = "Generate Groth16 CRS (proving key, verifying key, and Solidity verifier)")]
struct Cli {
    /// Output directory for CRS files
    #[arg(long)]
    output: String,

    /// Path to the JSON config file
    #[arg(long)]
    config: String,

    /// Profile name for manifest.json (e.g. "dev", "prod")
    #[arg(long, default_value = "dev")]
    profile: String,
}

fn main() {
    let cli = Cli::parse();

    // Ensure output directory exists before writing any files.
    let output_dir = std::path::Path::new(&cli.output);
    if let Err(e) = std::fs::create_dir_all(output_dir) {
        eprintln!("Failed to create output directory {}: {}", cli.output, e);
        std::process::exit(1);
    }

    let config_path = std::path::Path::new(&cli.config);
    let params =
        circuit::constants::CircuitConfig::from_json_file(config_path).unwrap_or_else(|e| {
            eprintln!("Failed to load config: {}", e);
            std::process::exit(1);
        });

    println!("Generate CRS files at path: {}", cli.output);
    println!("==================================================");
    println!(
        "  [JWT] Max Len: {}, Payload: {}",
        params.max_jwt_b64_len, params.max_payload_b64_len
    );
    println!(
        "  [JWT] Fields: Aud={}, Exp={}, Iss={}, Nonce={}, Sub={}",
        params.max_aud_len,
        params.max_exp_len,
        params.max_iss_len,
        params.max_nonce_len,
        params.max_sub_len
    );
    println!(
        "  [Logic] N={}, K={}, Height={}, NumAudienceLimit={}",
        params.n, params.k, params.tree_height, params.num_audience_limit
    );
    println!("==================================================");

    let setup_output = zkap_service::groth16_setup(&params).unwrap_or_else(|e| {
        eprintln!("Groth16 setup failed: {}", e);
        std::process::exit(1);
    });

    let pk_path = format!("{}/pk.key", cli.output);
    let vk_path = format!("{}/vk.key", cli.output);
    let pvk_path = format!("{}/pvk.key", cli.output);
    let sol_path = format!("{}/Groth16Verifier.sol", cli.output);

    to_file(&setup_output.pk, &pk_path).unwrap_or_else(|e| {
        eprintln!("Failed to write pk.key: {}", e);
        std::process::exit(1);
    });
    to_file(&setup_output.vk, &vk_path).unwrap_or_else(|e| {
        eprintln!("Failed to write vk.key: {}", e);
        std::process::exit(1);
    });
    to_file(&setup_output.pvk, &pvk_path).unwrap_or_else(|e| {
        eprintln!("Failed to write pvk.key: {}", e);
        std::process::exit(1);
    });

    setup_output.vk.generate_solidity(&sol_path);

    write_manifest(
        &cli.output,
        &cli.profile,
        &params,
        &[&pk_path, &vk_path, &pvk_path, &sol_path],
    );

    println!("CRS generation complete.");
}

fn write_manifest(
    dir: &str,
    profile: &str,
    params: &circuit::constants::CircuitConfig,
    files: &[&str],
) {
    if let Err(e) = std::fs::create_dir_all(dir) {
        panic!("Failed to create manifest directory {}: {}", dir, e);
    }

    let mut file_hashes = HashMap::new();
    for path in files {
        let filename = std::path::Path::new(path)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let hash = sha256_file(path);
        file_hashes.insert(filename, hash);
    }

    let manifest = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "profile": profile,
        "generated_at": unix_timestamp(),
        "params": {
            "MAX_JWT_B64_LEN": params.max_jwt_b64_len,
            "MAX_PAYLOAD_B64_LEN": params.max_payload_b64_len,
            "MAX_AUD_LEN": params.max_aud_len,
            "MAX_EXP_LEN": params.max_exp_len,
            "MAX_ISS_LEN": params.max_iss_len,
            "MAX_NONCE_LEN": params.max_nonce_len,
            "MAX_SUB_LEN": params.max_sub_len,
            "N": params.n,
            "K": params.k,
            "TREE_HEIGHT": params.tree_height,
            "NUM_AUDIENCE_LIMIT": params.num_audience_limit,
        },
        "files": file_hashes,
    });

    let manifest_path = format!("{}/manifest.json", dir);
    let json = serde_json::to_string_pretty(&manifest).expect("Failed to serialize manifest");
    std::fs::write(&manifest_path, &json).expect("Failed to write manifest.json");
    println!("Manifest written: {}", manifest_path);
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn sha256_file(path: &str) -> String {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("Failed to read {}: {}", path, e));
    let hash = Sha256::digest(&bytes);
    hex::encode(hash)
}

fn to_file<T: CanonicalSerialize>(value: &T, file_path: &str) -> Result<(), String> {
    let mut cursor = Cursor::new(Vec::new());

    let dir_path = std::path::Path::new(file_path).parent().unwrap();
    if !dir_path.exists()
        && let Err(err) = std::fs::create_dir_all(dir_path)
    {
        return Err(format!("Failed to create folder: {}", err));
    }

    if let Err(e) = value.serialize_uncompressed(&mut cursor) {
        return Err(format!("Failed to serialize: {}", e));
    }

    let mut file = match File::create(file_path) {
        Ok(f) => f,
        Err(e) => return Err(format!("Failed to create file: {}", e)),
    };

    if let Err(e) = file.write_all(cursor.get_ref()) {
        return Err(format!("Failed to write to file: {}", e));
    }

    Ok(())
}
