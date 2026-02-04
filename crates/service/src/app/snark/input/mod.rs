//! 입력 데이터 레이어
//!
//! Raw 문자열 입력을 타입 안전한 도메인 객체로 변환하는 모듈입니다.
//!
//! ## 아키텍처
//!
//! ```text
//! ┌─────────────────────┐
//! │   RawProofRequest   │  ← 외부에서 들어오는 원시 문자열 데이터
//! └──────────┬──────────┘
//!            │ validate & parse
//!            ▼
//! ┌─────────────────────┐
//! │   ProofRequest      │  ← 검증된 도메인 객체 (F 필드 요소들)
//! └──────────┬──────────┘
//!            │ build context
//!            ▼
//! ┌─────────────────────┐
//! │   ProofContext      │  ← 증명 생성에 필요한 모든 컨텍스트
//! └─────────────────────┘
//! ```

mod raw;
mod request;

pub use raw::RawProofRequest;
pub use request::ProofRequest;
