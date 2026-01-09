use ark_serialize::CanonicalSerialize;
use ark_std::rand::{self, RngCore, SeedableRng, rngs::OsRng};
use common::constants::{ZkapConfig, ZkPasskeyConfig};
use std::{
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
    use common::evm::groth16_verifier_solidity::SolidityContractGenerator;
    use gadget::bigint::constraints::BigNatCircuitParams;
    use gadget::hashes::mimc7;

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
    type BNP = BigNat2048Params;

    println!("Generate Baerae CRS files at path: {}", file_path);

    println!("==================================================");
    println!("⚙️  Configuring Circuit with the following parameters:");
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

    to_file::<ProvingKey<Bn254>>(&pk, &format!("{}/pk.key", file_path)).unwrap();
    to_file::<VerifyingKey<Bn254>>(&vk, &format!("{}/vk.key", file_path)).unwrap();
    to_file::<PreparedVerifyingKey<Bn254>>(&pvk, &format!("{}/pvk.key", file_path)).unwrap();
    vk.generate_solidity(&format!("{}/Groth16Verifier.sol", file_path));
}

#[allow(unused)]
fn to_file<T>(value: &T, file_path: &str) -> Result<(), String>
where
    T: CanonicalSerialize,
{
    let mut cursor = Cursor::new(Vec::new());

    let dir_path = std::path::Path::new(file_path).parent().unwrap();
    if !dir_path.exists() {
        if let Err(err) = std::fs::create_dir_all(dir_path) {
            return Err(format!("Failed to create folder: {}", err));
        }
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
