use ark_serialize::CanonicalSerialize;
use ark_std::rand::{self, RngCore, SeedableRng, rngs::OsRng};
use circuit::constants::{ZkapConfig, ZkPasskeyConfig};
use std::{
    collections::HashMap,
    env::args,
    fs::File,
    io::{Cursor, Write},
};

fn main() {
    if !cfg!(feature = "baerae") {
        eprintln!(
            "This binary must be run with `--features baerae` because it depends on the baerae circuit."
        );

        std::process::exit(1);
    };

    if !cfg!(feature = "num-cs-logging") {
        eprintln!(
            "This binary must be run with `--features num-cs-logging` to enable constraint analysis output."
        );

        std::process::exit(1);
    };

    let args: Vec<_> = args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run --features baerae --bin generate_baerae_crs <file_path>");
        std::process::exit(1);
    }

    let seed_u64 = OsRng.next_u64();
    let rng: rand::rngs::StdRng = ark_std::rand::rngs::StdRng::seed_from_u64(seed_u64);

    generate_crs_files(&args[1], rng);
}

#[allow(unused)]
fn generate_crs_files(file_path: &str, mut rng: rand::rngs::StdRng) {
    use circuit::evm::groth16_verifier_solidity::SolidityContractGenerator;
    use gadget::bigint::constraints::BigNatCircuitParams;

    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
    use ark_groth16::{
        Groth16, PreparedVerifyingKey, ProvingKey, VerifyingKey, prepare_verifying_key,
    };

    const LAMBDA: usize = 2048; // 512 bits
    #[derive(Clone, PartialEq, Eq, Debug)]
    struct BigNat2048Params;
    impl BigNatCircuitParams for BigNat2048Params {
        const LIMB_WIDTH: usize = 64;
        const N_LIMBS: usize = LAMBDA / 64;
    }

    type C = ark_ed_on_bn254::EdwardsProjective;
    type CV = ark_ed_on_bn254::constraints::EdwardsVar;
    #[allow(clippy::upper_case_acronyms)]
    type BNP = BigNat2048Params;

    println!("Generate Baerae CRS files at path: {}", file_path);

    println!("==================================================");
    println!("  Configuring Circuit with the following parameters:");
    println!(
        "   [JWT] Max Len: {}, Payload: {}",
        ZkapConfig::MAX_JWT_B64_LEN,
        ZkapConfig::MAX_PAYLOAD_B64_LEN
    );
    println!(
        "   [JWT] Fields: Aud={}, Exp={}, Iss={}, Nonce={}, Sub={}",
        ZkapConfig::MAX_AUD_LEN,
        ZkapConfig::MAX_EXP_LEN,
        ZkapConfig::MAX_ISS_LEN,
        ZkapConfig::MAX_NONCE_LEN,
        ZkapConfig::MAX_SUB_LEN
    );
    println!(
        "   [Logic] N={}, K={}, Height={}, NumAudienceLimit={}",
        ZkapConfig::N,
        ZkapConfig::K,
        ZkapConfig::TREE_HEIGHT,
        ZkapConfig::NUM_AUDIENCE_LIMIT
    );
    println!("   [Logic] PadChar='{}' (Fixed)", ZkapConfig::PAD_CHAR);
    println!("   [Logic] CLAIM_TYPES={:?} (Fixed)", ZkapConfig::CLAIMS);
    println!("==================================================");

    let circuit =
        circuit::baerae::BaeraeLightWeightCircuit::<C, BNP, ZkapConfig>::generate_mock_circuit();

    let (pk, vk) = Groth16::<Bn254>::setup(circuit, &mut rng).unwrap();
    let pvk = prepare_verifying_key(&vk);

    let pk_path = format!("{}/pk.key", file_path);
    let vk_path = format!("{}/vk.key", file_path);
    let pvk_path = format!("{}/pvk.key", file_path);
    let sol_path = format!("{}/Groth16Verifier.sol", file_path);

    to_file::<ProvingKey<Bn254>>(&pk, &pk_path).unwrap();
    to_file::<VerifyingKey<Bn254>>(&vk, &vk_path).unwrap();
    to_file::<PreparedVerifyingKey<Bn254>>(&pvk, &pvk_path).unwrap();
    vk.generate_solidity(&sol_path);

    // Generate manifest.json with parameters and file hashes
    write_manifest(file_path, &[&pk_path, &vk_path, &pvk_path, &sol_path]);
}

fn write_manifest(dir: &str, files: &[&str]) {
    let profile = std::env::var("ZK_PROFILE").unwrap_or_else(|_| "dev".to_string());
    let now = chrono_rfc3339_now();

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
        "generated_at": now,
        "params": {
            "MAX_JWT_B64_LEN": ZkapConfig::MAX_JWT_B64_LEN,
            "MAX_PAYLOAD_B64_LEN": ZkapConfig::MAX_PAYLOAD_B64_LEN,
            "MAX_AUD_LEN": ZkapConfig::MAX_AUD_LEN,
            "MAX_EXP_LEN": ZkapConfig::MAX_EXP_LEN,
            "MAX_ISS_LEN": ZkapConfig::MAX_ISS_LEN,
            "MAX_NONCE_LEN": ZkapConfig::MAX_NONCE_LEN,
            "MAX_SUB_LEN": ZkapConfig::MAX_SUB_LEN,
            "N": ZkapConfig::N,
            "K": ZkapConfig::K,
            "TREE_HEIGHT": ZkapConfig::TREE_HEIGHT,
            "NUM_AUDIENCE_LIMIT": ZkapConfig::NUM_AUDIENCE_LIMIT,
        },
        "files": file_hashes,
    });

    let manifest_path = format!("{}/manifest.json", dir);
    let json = serde_json::to_string_pretty(&manifest).expect("Failed to serialize manifest");
    std::fs::write(&manifest_path, &json).expect("Failed to write manifest.json");

    println!("Manifest written: {}", manifest_path);
}

fn sha256_file(path: &str) -> String {
    let output = std::process::Command::new("shasum")
        .args(["-a", "256", path])
        .output()
        .unwrap_or_else(|e| panic!("Failed to run shasum on {}: {}", path, e));
    let stdout = String::from_utf8_lossy(&output.stdout);
    // shasum output: "<hash>  <filename>\n"
    stdout.split_whitespace().next().unwrap_or("unknown").to_string()
}

fn chrono_rfc3339_now() -> String {
    // Simple UTC timestamp without chrono dependency
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let secs = duration.as_secs();
    // Approximate: good enough for a build manifest timestamp
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since epoch to date (simplified Gregorian)
    let mut y = 1970i64;
    let mut remaining = days as i64;
    loop {
        let year_days = if is_leap(y) { 366 } else { 365 };
        if remaining < year_days {
            break;
        }
        remaining -= year_days;
        y += 1;
    }
    let month_days: [i64; 12] = if is_leap(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut m = 0usize;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining < md {
            m = i;
            break;
        }
        remaining -= md;
    }
    let d = remaining + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m + 1,
        d,
        hours,
        minutes,
        seconds
    )
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

#[allow(unused)]
fn to_file<T>(value: &T, file_path: &str) -> Result<(), String>
where
    T: CanonicalSerialize,
{
    let mut cursor = Cursor::new(Vec::new());

    let dir_path = std::path::Path::new(file_path).parent().unwrap();
    if !dir_path.exists()
        && let Err(err) = std::fs::create_dir_all(dir_path) {
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
