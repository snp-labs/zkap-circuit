//! ZKAP 증명 생성 서비스 (리팩토링 버전)
//!
//! ## 아키텍처
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     generate_baerae_proof_v2                    │
//! │                        (엔트리 포인트)                             │
//! └───────────────────────────────┬─────────────────────────────────┘
//!                                 │
//!                 ┌───────────────┼───────────────┐
//!                 ▼               ▼               ▼
//! ┌───────────────────┐ ┌─────────────────┐ ┌─────────────────────┐
//! │  RawProofRequest  │ │  ProofRequest   │ │ ProofContextBuilder │
//! │   (입력 수집)        │→│  (검증/파싱)     │→│    (컨텍스트 구축)      │
//! └───────────────────┘ └─────────────────┘ └──────────┬──────────┘
//!                                                      │
//!                                                      ▼
//!                                          ┌──────────────────────┐
//!                                          │    CircuitInput[]    │
//!                                          │ (회로 입력 구조체들)     │
//!                                          └──────────┬───────────┘
//!                                                     │
//!                                                     ▼
//!                                          ┌──────────────────────┐
//!                                          │   ProofGenerator     │
//!                                          │   (증명 생성)          │
//!                                          └──────────┬───────────┘
//!                                                     │
//!                                                     ▼
//!                                          ┌──────────────────────┐
//!                                          │    ProofOutput       │
//!                                          │ (증명 + 공개입력)       │
//!                                          └──────────────────────┘
//! ```

use ark_groth16::Proof;
use circuit::constants::{BN254, F, ZkPasskeyConfig};
use log;

use crate::error::ApplicationError;

use super::context::ProofContextBuilder;
use super::input::{ProofRequest, RawProofRequest};
use super::proof::ProofGenerator;

/// 1. RawProofRequest → ProofRequest (검증 및 파싱)
/// 2. ProofRequest → CircuitInput[] (컨텍스트 구축)
/// 3. CircuitInput[] → Proof[] (증명 생성)
///
/// # Arguments
/// * `raw` - 원시 증명 요청 데이터
///
/// # Returns
/// * 증명들과 공개 입력들의 튜플
#[allow(clippy::type_complexity)]
pub fn generate_baerae_proof<Config: ZkPasskeyConfig>(
    raw: RawProofRequest,
) -> Result<(Vec<Proof<BN254>>, Vec<Vec<F>>), ApplicationError> {
    // 1. 입력 검증 및 파싱
    log::info!("[ZKAP-v2] Step 1: Validating and parsing inputs...");
    let request = ProofRequest::from_raw::<Config>(raw)?;
    log::info!("[ZKAP-v2] Step 1 completed: Input validation passed");

    // 2. 컨텍스트 구축
    log::info!("[ZKAP-v2] Step 2: Building proof context...");
    let builder = ProofContextBuilder::<Config>::new(request.clone())
        .build_anchor_context()?
        .build_audience_context()?;
    log::info!("[ZKAP-v2] Step 2 completed: Context built");

    // 3. 회로 입력 생성
    log::info!("[ZKAP-v2] Step 3: Building circuit inputs...");
    let circuit_inputs = builder.build_all_circuit_inputs()?;
    log::info!(
        "[ZKAP-v2] Step 3 completed: {} circuit inputs created",
        circuit_inputs.len()
    );

    // 4. 증명 생성
    log::info!("[ZKAP-v2] Step 4: Generating proofs...");
    let generator = ProofGenerator::new(request.pk_path.clone());

    let output = generator.generate::<Config>(&circuit_inputs)?;

    log::info!(
        "[ZKAP-v2] Step 4 completed: {} proofs generated",
        output.proofs.len()
    );

    Ok((output.proofs, output.public_inputs))
}
