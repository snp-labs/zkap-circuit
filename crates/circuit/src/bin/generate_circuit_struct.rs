fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: \n<out_circuit.arkwork>");
        std::process::exit(1);
    }

    let out_filename = &args[1];
    generate_r1cs_files(out_filename);
}

fn generate_r1cs_files(file_path: &str) {
    use ark_serialize::CanonicalSerialize;
    use circuit::constants::{BNP, CG, ZkapConfig, ZkPasskeyConfig};
    use std::fs::File;
    use std::io::Write;

    println!("Generating R1CS for BaeraeLightWeightCircuit...");

    println!("ZkapConfig parameters:");
    println!("MAX_JWT_B64_LEN: {}", <ZkapConfig as ZkPasskeyConfig>::MAX_JWT_B64_LEN);
    println!("MAX_PAYLOAD_B64_LEN: {}", <ZkapConfig as ZkPasskeyConfig>::MAX_PAYLOAD_B64_LEN);
    println!("MAX_AUD_LEN: {}", <ZkapConfig as ZkPasskeyConfig>::MAX_AUD_LEN);
    println!("MAX_EXP_LEN: {}", <ZkapConfig as ZkPasskeyConfig>::MAX_EXP_LEN);
    println!("MAX_ISS_LEN: {}", <ZkapConfig as ZkPasskeyConfig>::MAX_ISS_LEN);
    println!("MAX_NONCE_LEN: {}", <ZkapConfig as ZkPasskeyConfig>::MAX_NONCE_LEN);
    println!("MAX_SUB_LEN: {}", <ZkapConfig as ZkPasskeyConfig>::MAX_SUB_LEN);
    println!("N: {}", <ZkapConfig as ZkPasskeyConfig>::N);
    println!("K: {}", <ZkapConfig as ZkPasskeyConfig>::K);
    println!("TREE_HEIGHT: {}", <ZkapConfig as ZkPasskeyConfig>::TREE_HEIGHT);
    println!("CLAIMS: {:?}", <ZkapConfig as ZkPasskeyConfig>::CLAIMS);
    println!("NUM_AUDIENCE_LIMIT: {}", <ZkapConfig as ZkPasskeyConfig>::NUM_AUDIENCE_LIMIT);
    println!("FORBIDDEN_STRING: {}", <ZkapConfig as ZkPasskeyConfig>::FORBIDDEN_STRING);
    println!("PAD_CHAR: {}", <ZkapConfig as ZkPasskeyConfig>::PAD_CHAR);

    let circuit = circuit::baerae::BaeraeLightWeightCircuit::<CG, BNP, ZkapConfig>::generate_mock_circuit();

    let mut bytes = Vec::new();
    circuit.serialize_uncompressed(&mut bytes).unwrap();

    let mut file = File::create(file_path).unwrap();
    file.write_all(&bytes).unwrap();

    println!("R1CS file exported to {}", file_path);
}
