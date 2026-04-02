use std::fs::File;

use ark_crypto_primitives::crh::CRHScheme;
use ark_ff::PrimeField;
use clap::{Args, Parser, Subcommand, command};
use circuit::constants::{BNP, CG, F, PoseidonHash, ZkPasskeyConfig, ZkapConfig};
use gadget::{
    base64::decode_any_base64, hashes::poseidon::get_poseidon_params, signature::rsa::PublicKey, utils::str_to_limbs
};
use serde::Serialize;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate hash for audience list with padding
    Aud(AudArgs),

    /// Generate leaves from iss and pk lists
    Leaf(LeafArgs),
}

#[derive(Args)]
struct AudArgs {
    /// Audience values separated by comma (e.g. "google.com, facebook.com")
    #[arg(short, long)]
    values: String,

    /// Output json file path
    #[arg(short, long, default_value = "aud_output.json")]
    out: String,
}

#[derive(Args)]
struct LeafArgs {
    /// Issuer strings separated by comma (e.g. "iss1, iss2")
    #[arg(long)]
    iss: String,

    /// Public key strings separated by comma (e.g. "pk1, pk2")
    #[arg(long)]
    pk: String,

    /// Output json file path
    #[arg(short, long, default_value = "leaf_output.json")]
    out: String,
}

#[derive(Serialize)]
struct AudItem {
    aud_to_field: Vec<String>,
    h_aud_lists: String,
}

#[derive(Serialize)]
struct AudOutput {
    input: Vec<String>,
    output: AudItem,
}

// 결과의 각 항목을 담을 구조체
#[derive(Serialize)]
struct LeafInput {
    iss: String,
    pk: String,
}

// 전체 결과를 담을 구조체 (선택 사항, 바로 Vec<LeafItem>을 저장해도 됨)
#[derive(Serialize)]
struct LeafOutput {
    input: Vec<LeafInput>,
    output: Vec<String>,
}

fn main() {
    // 파싱이 여기서 한 방에 끝납니다.
    let cli = Cli::parse();

    // 어떤 커맨드인지 패턴 매칭만 하면 됩니다.
    match &cli.command {
        Commands::Aud(args) => generate_aud_hash(&args),
        Commands::Leaf(args) => generate_pk_leaf(&args),
    }
}

fn generate_aud_hash(args: &AudArgs) {
    let params = get_poseidon_params::<F>();

    let mut aud_vec: Vec<String> = args
        .values
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    if aud_vec.len() > ZkapConfig::NUM_AUDIENCE_LIMIT {
        eprintln!(
            "Error: Input audience count ({}) exceeds the limit ({}).",
            aud_vec.len(),
            ZkapConfig::NUM_AUDIENCE_LIMIT
        );
        std::process::exit(1);
    }

    while aud_vec.len() < ZkapConfig::NUM_AUDIENCE_LIMIT {
        aud_vec.push(ZkapConfig::FORBIDDEN_STRING.to_string());
    }

    let aud_fields: Vec<F> = aud_vec
        .iter()
        .map(|a| {
            let limbs = str_to_limbs(a, ZkapConfig::MAX_AUD_LEN, ZkapConfig::PAD_CHAR as u8);
            let h = PoseidonHash::evaluate(&params, limbs).unwrap_or_else(|e| {
                eprintln!("Error processing aud '{}': {}", a, e);
                std::process::exit(1);
            });
            h
        })
        .collect();
    let h_aud_lists = PoseidonHash::evaluate(&params, &*aud_fields).unwrap_or_else(|e| {
        eprintln!("Error computing h_aud_lists: {}", e);
        std::process::exit(1);
    });

    let output = AudOutput {
        input: aud_vec,
        output: AudItem {
            aud_to_field: aud_fields
                .iter()
                .map(|f| format!("0x{:X}", f.into_bigint()))
                .collect(),
            h_aud_lists: format!("0x{:X}", h_aud_lists.into_bigint()),
        },
    };

    write_json(&args.out, &output);
    println!("Successfully generated aud hashes to {}", &args.out);
}

fn generate_pk_leaf(args: &LeafArgs) {
    let params = get_poseidon_params::<F>();

    // 1. 콤마로 구분하여 리스트로 파싱
    let iss_list: Vec<&str> = args.iss.split(',').map(|s| s.trim()).collect();
    let pk_list: Vec<&str> = args.pk.split(',').map(|s| s.trim()).collect();

    // 2. 개수 일치 확인
    if iss_list.len() != pk_list.len() {
        eprintln!(
            "Error: Mismatch in input counts. iss count: {}, pk count: {}",
            iss_list.len(),
            pk_list.len()
        );
        std::process::exit(1);
    }

    println!("Processing {} items...", iss_list.len());

    // RSA Exponent 'AQAB' (65537) 미리 디코딩
    let e_decoded = decode_any_base64("AQAB").unwrap_or_else(|e| {
        eprintln!("Error decoding exponent 'AQAB': {}", e);
        std::process::exit(1);
    });

    // 3. 각 쌍(Pair) 처리 및 분리 (unzip 사용)
    let (inputs, outputs): (Vec<LeafInput>, Vec<String>) = iss_list
        .iter()
        .zip(pk_list.iter())
        .map(|(&iss, &pk)| {
            // --- (1) Input 구조체 생성 ---
            let input_data = LeafInput {
                iss: iss.to_string(),
                pk: pk.to_string(),
            };

            // --- (2) 로직 처리 ---
            // Issuer Limbs 변환
            let iss_limbs = str_to_limbs(iss, ZkapConfig::MAX_ISS_LEN, ZkapConfig::PAD_CHAR as u8);

            // Public Key 디코딩 및 Limbs 변환
            let n_decoded = decode_any_base64(pk).unwrap_or_else(|e| {
                eprintln!("Error decoding pk '{}': {}", pk, e);
                std::process::exit(1);
            });

            let pk_obj = PublicKey {
                n: n_decoded,
                e: e_decoded.clone(),
            };

            // pk.to_limbs가 튜플(.0)을 반환한다고 가정
            let n_limbs = pk_obj.to_limbs::<BNP, CG>().0;

            // Leaf Hash = Hash(iss_limbs || n_limbs)
            // 두 벡터를 합쳐서 하나의 해시 입력으로 사용
            let mut leaf_inputs = Vec::new();
            leaf_inputs.extend_from_slice(&iss_limbs);
            leaf_inputs.extend_from_slice(&n_limbs);

            let leaf = PoseidonHash::evaluate(&params, &*leaf_inputs).unwrap_or_else(|e| {
                eprintln!("Error computing leaf for iss '{}': {}", iss, e);
                std::process::exit(1);
            });

            // 결과값 (Hex String)
            let leaf_hex = format!("0x{:X}", leaf.into_bigint());

            (input_data, leaf_hex)
        })
        .unzip(); // 튜플 벡터를 두 개의 벡터로 분리

    // 4. 결과 저장
    let output_struct = LeafOutput {
        input: inputs,
        output: outputs,
    };

    write_json(&args.out, &output_struct);
    println!(
        "Successfully generated {} leaves to {}",
        output_struct.output.len(),
        args.out
    );
}

fn write_json<T: Serialize>(path: &str, data: &T) {
    let file = File::create(path).expect("Failed to create output file");
    serde_json::to_writer_pretty(file, data).expect("Failed to write JSON");
}
