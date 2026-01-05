use ark_crypto_primitives::sponge::Absorb;
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_serialize::*;
use ark_std::vec::Vec;

/// A proof in the Groth16 SNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<E: Pairing> {
    /// The `A` element in `G1`.
    pub a: E::G1Affine,
    /// The `B` element in `G2`.
    pub b: E::G2Affine,
    /// The `C` element in `G1`.
    pub c: E::G1Affine,
}

impl<E: Pairing> Default for Proof<E> {
    fn default() -> Self {
        Self {
            a: E::G1Affine::default(),
            b: E::G2Affine::default(),
            c: E::G1Affine::default(),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// A verification key in the Groth16 SNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifyingKey<E: Pairing> {
    /// The `alpha * G`, where `G` is the generator of `E::G1`.
    pub alpha_g1: E::G1Affine,
    /// The `alpha * H`, where `H` is the generator of `E::G2`.
    pub beta_g2: E::G2Affine,
    /// The `gamma * H`, where `H` is the generator of `E::G2`.
    pub gamma_g2: E::G2Affine,
    /// The `delta * H`, where `H` is the generator of `E::G2`.
    pub delta_g2: E::G2Affine,
    /// The `gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * H`, where `H` is
    /// the generator of `E::G1`.
    pub gamma_abc_g1: Vec<E::G1Affine>,
}

impl<E: Pairing> Default for VerifyingKey<E> {
    fn default() -> Self {
        Self {
            alpha_g1: E::G1Affine::default(),
            beta_g2: E::G2Affine::default(),
            gamma_g2: E::G2Affine::default(),
            delta_g2: E::G2Affine::default(),
            gamma_abc_g1: Vec::new(),
        }
    }
}

impl<E> Absorb for VerifyingKey<E>
where
    E: Pairing,
    E::G1Affine: Absorb,
    E::G2Affine: Absorb,
{
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        self.alpha_g1.to_sponge_bytes(dest);
        self.beta_g2.to_sponge_bytes(dest);
        self.gamma_g2.to_sponge_bytes(dest);
        self.delta_g2.to_sponge_bytes(dest);
        self.gamma_abc_g1
            .iter()
            .for_each(|g| g.to_sponge_bytes(dest));
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.alpha_g1.to_sponge_field_elements(dest);
        self.beta_g2.to_sponge_field_elements(dest);
        self.gamma_g2.to_sponge_field_elements(dest);
        self.delta_g2.to_sponge_field_elements(dest);
        self.gamma_abc_g1
            .iter()
            .for_each(|g| g.to_sponge_field_elements(dest));
    }
}

/// Preprocessed verification key parameters that enable faster verification
/// at the expense of larger size in memory.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PreparedVerifyingKey<E: Pairing> {
    /// The unprepared verification key.
    pub vk: VerifyingKey<E>,
    /// The element `e(alpha * G, beta * H)` in `E::GT`.
    pub alpha_g1_beta_g2: E::TargetField,
    /// The element `- gamma * H` in `E::G2`, prepared for use in pairings.
    pub gamma_g2_neg_pc: E::G2Prepared,
    /// The element `- delta * H` in `E::G2`, prepared for use in pairings.
    pub delta_g2_neg_pc: E::G2Prepared,
}

impl<E: Pairing> From<PreparedVerifyingKey<E>> for VerifyingKey<E> {
    fn from(other: PreparedVerifyingKey<E>) -> Self {
        other.vk
    }
}

impl<E: Pairing> From<VerifyingKey<E>> for PreparedVerifyingKey<E> {
    fn from(other: VerifyingKey<E>) -> Self {
        crate::prepare_verifying_key(&other)
    }
}

impl<E: Pairing> Default for PreparedVerifyingKey<E> {
    fn default() -> Self {
        Self {
            vk: VerifyingKey::default(),
            alpha_g1_beta_g2: E::TargetField::default(),
            gamma_g2_neg_pc: E::G2Prepared::default(),
            delta_g2_neg_pc: E::G2Prepared::default(),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// The prover key for for the Groth16 zkSNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvingKey<E: Pairing> {
    /// The underlying verification key.
    pub vk: VerifyingKey<E>,
    /// The element `beta * G` in `E::G1`.
    pub beta_g1: E::G1Affine,
    /// The element `delta * G` in `E::G1`.
    pub delta_g1: E::G1Affine,
    /// The elements `a_i * G` in `E::G1`.
    pub a_query: Vec<E::G1Affine>,
    /// The elements `b_i * G` in `E::G1`.
    pub b_g1_query: Vec<E::G1Affine>,
    /// The elements `b_i * H` in `E::G2`.
    pub b_g2_query: Vec<E::G2Affine>,
    /// The elements `h_i * G` in `E::G1`.
    pub h_query: Vec<E::G1Affine>,
    /// The elements `l_i * G` in `E::G1`.
    pub l_query: Vec<E::G1Affine>,
}
/// CSR-like flat sparse matrix.
/// Row r has entries in k ∈ row_start[r]..row_start[r+1].
#[derive(Clone, Debug)]
pub struct FlatMatrix<F: Field> {
    /// 각 행(Row)의 시작 인덱스를 가리키는 포인터 배열 (CSR 포맷의 row_ptr)
    pub ptr: Vec<usize>,
    /// 비영(Non-zero) 원소가 위치한 열(Column/Variable) 인덱스
    pub col: Vec<u32>, // 메모리 절약을 위해 usize 대신 u32 사용 권장
    /// 비영 원소의 계수 값
    pub val: Vec<F>,
}

impl<F: Field> FlatMatrix<F> {
    /// 특정 행(row)에 해당하는 데이터의 범위(start..end)를 반환
    #[inline(always)]
    pub fn row_range(&self, row: usize) -> (usize, usize) {
        // ptr은 num_constraints + 1 크기여야 함
        (self.ptr[row], self.ptr[row + 1])
    }
}

/// Convert `Matrix<F> = Vec<Vec<(F, usize)>>` into FlatMatrix.
/// (F, usize) means (coeff, var_index).
pub fn flatten_matrix<F: Field + Copy>(
    m: &Vec<Vec<(F, usize)>>,
    num_rows: usize,
    nnz_hint: usize,
) -> FlatMatrix<F> {
    let mut row_start = Vec::with_capacity(num_rows + 1);
    row_start.push(0);

    let mut col = Vec::with_capacity(nnz_hint);
    let mut val = Vec::with_capacity(nnz_hint);

    for row in m.iter() {
        for (c, idx) in row.iter() {
            col.push(*idx as u32);
            val.push(*c);
        }
        row_start.push(col.len());
    }

    FlatMatrix {
        ptr: row_start,
        col,
        val,
    }
}
