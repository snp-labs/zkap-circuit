use core::{borrow::Borrow, cmp::max, marker::PhantomData};

use ark_ff::{BitIteratorBE, PrimeField};
use ark_r1cs_std::{
    R1CSVar,
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    prelude::{Boolean, ToBytesGadget},
    select::CondSelectGadget,
    uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use num::Zero;
use num_integer::Integer;
use num_traits::One;

use std::fmt::Debug;

use crate::bigint::utils::{
    fe_to_nat, field_characteristic_to_nat, fit_nat_to_limbs, limbs_to_nat, nat_to_fe,
};

use super::utils::{BigNat, nat_to_limbs};

pub trait BigNatCircuitParams: Clone + Debug + Eq + PartialEq + Send + Sync {
    const LIMB_WIDTH: usize;
    const N_LIMBS: usize;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RangeMode {
    Checked,
    Unchecked,
}

//TODO: Track word_size in number of bits rather than value
#[derive(Clone, Default)]
pub struct BigNatVar<ConstraintF: PrimeField, P: BigNatCircuitParams> {
    pub limbs: Vec<FpVar<ConstraintF>>, // Must be of length P::N_LIMBS
    pub value: BigNat,
    pub word_size: BigNat,
    pub _params: PhantomData<P>,
}

impl<ConstraintF: PrimeField, P: BigNatCircuitParams> AllocVar<BigNat, ConstraintF>
    for BigNatVar<ConstraintF, P>
{
    fn new_variable<T: Borrow<BigNat>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let f_out = f()?;
        let limbs = nat_to_limbs(f_out.borrow(), P::LIMB_WIDTH, P::N_LIMBS);
        let limb_vars = Vec::<FpVar<ConstraintF>>::new_variable(cs, || Ok(&limbs[..]), mode)?;
        Ok(BigNatVar {
            limbs: limb_vars,
            value: f_out.borrow().clone(),
            word_size: (BigNat::one() << P::LIMB_WIDTH as u32) - BigNat::one(),
            _params: PhantomData,
        })
    }
}

impl<ConstraintF: PrimeField, P: BigNatCircuitParams> R1CSVar<ConstraintF>
    for BigNatVar<ConstraintF, P>
{
    type Value = BigNat;

    fn cs(&self) -> ConstraintSystemRef<ConstraintF> {
        self.limbs.as_slice().cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        debug_assert_eq!(self.limbs.len(), P::N_LIMBS);
        let limbs = self
            .limbs
            .iter()
            .map(|f| f.value())
            .collect::<Result<Vec<ConstraintF>, SynthesisError>>()?;
        let value = limbs_to_nat::<ConstraintF>(&limbs, P::LIMB_WIDTH);
        debug_assert_eq!(self.value, value);
        Ok(value)
    }
}

impl<ConstraintF: PrimeField, P: BigNatCircuitParams> BigNatVar<ConstraintF, P> {
    #[inline(always)]
    fn maybe_enforce_limb_range(&self, mode: RangeMode) -> Result<(), SynthesisError> {
        if matches!(mode, RangeMode::Checked) {
            // Skip range check for un-normalized representations
            // where word_size > 2^LIMB_WIDTH - 1
            let max_canonical_word_size = (BigNat::one() << P::LIMB_WIDTH as u32) - BigNat::one();
            if self.word_size <= max_canonical_word_size {
                self.enforce_limb_range_via_bits()?;
            }
        }
        Ok(())
    }

    /// 상수 생성 (제약 시스템에 연결하지 않음)
    /// Create constant without reference to constraint system
    pub fn constant(nat: &BigNat) -> Result<Self, SynthesisError> {
        let limbs = nat_to_limbs::<ConstraintF>(nat, P::LIMB_WIDTH, P::N_LIMBS);
        let limb_vars = limbs
            .iter()
            .map(|l| <FpVar<ConstraintF>>::constant(l.clone()))
            .collect::<Vec<FpVar<ConstraintF>>>();
        Ok(BigNatVar {
            limbs: limb_vars,
            value: nat.clone(),
            word_size: (BigNat::one() << P::LIMB_WIDTH as u32) - BigNat::one(),
            _params: PhantomData,
        })
    }

    /// BigNatVar를 canonical limb 표현으로 “정규화(reduce)”하는 함수
    /// - 입력 limb를 range-check로 정리
    /// - 같은 값을 나타내는지(carry 고려) out과의 동등성 제약을 추가
    pub fn reduce(&self) -> Result<Self, SynthesisError> {
        // 입력 limb가 <2^w 임을 강제
        self.enforce_limb_range_via_bits()?;

        let cs = self.cs();
        if cs != ConstraintSystemRef::None {
            // 동일한 value로 새로운 witness를 만들고(out), out도 canonical 강제
            // 그리고 carry를 허용한 동등성(self == out)을 제약으로 연결
            let reduced = Self::new_witness(cs.clone(), || Ok(&self.value))?;
            reduced.enforce_limb_range_via_bits()?;
            self.enforce_equal_when_carried(&reduced)?;
            Ok(reduced)
        } else {
            // CS가 없으면 그냥 constant로 반환
            Ok(Self::constant(&self.value)?)
        }
    }

    /// 덧셈(Checked): 입력 limb range-check 포함 + 출력은 canonical
    pub fn add(&self, other: &Self) -> Result<Self, SynthesisError> {
        self.add_mode(other, RangeMode::Checked)
    }

    /// 덧셈(Unchecked): 입력 range-check 생략 + 출력만 canonical
    pub fn add_unchecked(&self, other: &Self) -> Result<Self, SynthesisError> {
        self.add_mode(other, RangeMode::Unchecked)
    }

    /// 덧셈 공통 로직:
    /// - (선택) 입력 range-check
    /// - field wrap(모듈러 필드에서 값이 접히는 현상) 위험이면 Unsatisfiable로 실패
    /// - tmp=self+other(캐리 미전파)와 out(정규화 witness)을 carry-동등성으로 연결
    pub fn add_mode(&self, other: &Self, mode: RangeMode) -> Result<Self, SynthesisError> {
        self.maybe_enforce_limb_range(mode)?;
        other.maybe_enforce_limb_range(mode)?;

        let cs = self.cs().or(other.cs());

        // 누산 상계가 필드 크기 이상이면 FpVar 덧셈이 “정수 덧셈” 의미를 잃을 수 있으므로 실패
        let field_char = field_characteristic_to_nat::<ConstraintF>();
        let max_word_size = &self.word_size + &other.word_size;
        if max_word_size >= field_char {
            return Err(SynthesisError::Unsatisfiable);
        }

        let sum_value = &self.value + &other.value;
        let out = Self::new_witness(cs.clone(), || Ok(sum_value.clone()))?;
        out.enforce_limb_range_via_bits()?; // 출력 canonical

        // tmp는 limb-wise로 단순 합(캐리 전파 전) 상태를 표현
        // tmp == out 을 carry를 허용한 형태로 제약하여 정수 의미를 보존
        let tmp_limbs = self
            .limbs
            .iter()
            .zip(other.limbs.iter())
            .map(|(a, b)| a + b)
            .collect::<Vec<_>>();

        let tmp = Self {
            limbs: tmp_limbs,
            value: sum_value,
            word_size: max_word_size,
            _params: PhantomData,
        };

        tmp.enforce_equal_when_carried(&out)?;
        Ok(out)
    }

    /// 뺄셈(Checked): 입력 range-check 포함 + 출력 canonical
    pub fn sub(&self, other: &Self) -> Result<Self, SynthesisError> {
        self.sub_mode(other, RangeMode::Checked)
    }

    /// 뺄셈(Unchecked): 입력 range-check 생략 + 출력 canonical
    pub fn sub_unchecked(&self, other: &Self) -> Result<Self, SynthesisError> {
        self.sub_mode(other, RangeMode::Unchecked)
    }

    /// 뺄셈 공통 로직:
    /// - (선택) 입력 range-check
    /// - field wrap 방지 상계 체크
    /// - diff를 witness로 만들고 canonical 강제
    /// - other + diff == self 를 carry-동등성으로 연결(뺄셈의 정수 의미를 제약으로 확보)
    pub fn sub_mode(&self, other: &Self, mode: RangeMode) -> Result<Self, SynthesisError> {
        self.maybe_enforce_limb_range(mode)?;
        other.maybe_enforce_limb_range(mode)?;

        let cs = self.cs().or(other.cs());

        let field_char = field_characteristic_to_nat::<ConstraintF>();
        let max_word_size = max(&self.word_size, &other.word_size) + BigNat::one();
        if max_word_size >= field_char {
            return Err(SynthesisError::Unsatisfiable);
        }

        // off-circuit로 diff 계산(언더플로우는 0으로 클램프)
        // 실제 의미(자연수 뺄셈) 보장은 아래 제약(other+diff==self)로 강제됨
        let diff_value = if self.value >= other.value {
            &self.value - &other.value
        } else {
            BigNat::zero()
        };

        let diff = Self::new_witness(cs.clone(), || Ok(diff_value.clone()))?;
        diff.enforce_limb_range_via_bits()?; // 출력 canonical

        // other + diff == self 를 제약으로 강제(캐리 포함)
        let sum = other.add_mode(&diff, RangeMode::Unchecked)?;
        self.enforce_equal_when_carried(&sum)?;
        Ok(diff)
    }

    /// 곱셈(Checked): 입력 range-check 포함

    pub fn mult(&self, other: &Self) -> Result<Self, SynthesisError> {
        self.mult_mode(other, RangeMode::Checked)
    }

    /// 곱셈(Unchecked): 입력 range-check 생략
    pub fn mult_unchecked(&self, other: &Self) -> Result<Self, SynthesisError> {
        self.mult_mode(other, RangeMode::Unchecked)
    }

    /// 곱셈 공통 로직:
    /// - (선택) 입력 range-check
    /// - 누산 상계(word_size)가 필드보다 커지면 정수 의미가 깨질 수 있으므로 실패
    /// - limb 컨볼루션(2N-1) 형태로 곱 결과 limb 표현을 구성(캐리 전파는 하지 않음)
    pub fn mult_mode(&self, other: &Self, mode: RangeMode) -> Result<Self, SynthesisError> {
        self.maybe_enforce_limb_range(mode)?;
        other.maybe_enforce_limb_range(mode)?;

        let field_char = field_characteristic_to_nat::<ConstraintF>();
        let max_word_size =
            &self.word_size * &other.word_size * BigNat::from(P::N_LIMBS * P::N_LIMBS);
        if max_word_size >= field_char {
            return Err(SynthesisError::Unsatisfiable);
        }

        // 학교식(long multiplication) 컨볼루션(캐리 미포함)
        let mut prod_limbs = vec![FpVar::<ConstraintF>::zero(); 2 * P::N_LIMBS - 1];
        for i in 0..P::N_LIMBS {
            for j in 0..P::N_LIMBS {
                prod_limbs[i + j] += &self.limbs[i] * &other.limbs[j];
            }
        }

        let value = &self.value * &other.value;
        Ok(Self {
            limbs: prod_limbs,
            value,
            word_size: max_word_size,
            _params: PhantomData,
        })
    }

    /// 모듈러 곱(Checked): 일반 목적(제네릭) 구현
    pub fn mult_mod(&self, other: &Self, modulus: &Self) -> Result<Self, SynthesisError> {
        self.mult_mod_mode(other, modulus, RangeMode::Checked)
    }

    /// 모듈러 곱(Unchecked): RSA2048 signature verify 최적화를 위한 fast-path 엔트리
    pub fn mult_mod_unchecked(&self, other: &Self, modulus: &Self) -> Result<Self, SynthesisError> {
        self.mult_mod_mode(other, modulus, RangeMode::Unchecked)
    }

    /// mult_mod 통합 엔트리:
    /// - Checked: 제네릭한 안전 구현(quotient를 2N limb로 잡아도 안전)
    /// - Unchecked: RSA2048 signature verify용 fast-path(입력 range-check만 생략 + quotient를 N limb로 제한)
    pub fn mult_mod_mode(
        &self,
        other: &Self,
        modulus: &Self,
        mode: RangeMode,
    ) -> Result<Self, SynthesisError> {
        match mode {
            RangeMode::Checked => self.mult_mod_checked_impl(other, modulus),
            RangeMode::Unchecked => self.mult_mod_unchecked_impl(other, modulus),
        }
    }

    /// (제네릭) 모듈러 곱:
    /// rem = self*other mod modulus 를 증명하기 위해 quotient/rem을 witness로 두고,
    /// self*other == modulus*quotient + rem 과 rem < modulus 를 제약으로 강제
    fn mult_mod_checked_impl(&self, other: &Self, modulus: &Self) -> Result<Self, SynthesisError> {
        // Skip range check for un-normalized representations
        let max_canonical_word_size = (BigNat::one() << P::LIMB_WIDTH as u32) - BigNat::one();
        if self.word_size <= max_canonical_word_size {
            self.enforce_limb_range_via_bits()?;
        }
        if other.word_size <= max_canonical_word_size {
            other.enforce_limb_range_via_bits()?;
        }
        if modulus.word_size <= max_canonical_word_size {
            modulus.enforce_limb_range_via_bits()?;
        }
        let cs = self.cs().or(other.cs()).or(modulus.cs());

        // modulus != 0 강제
        if cs != ConstraintSystemRef::None {
            let zero = FpVar::<ConstraintF>::zero();
            let mut all_zero = Boolean::<ConstraintF>::TRUE;
            for l in modulus.limbs.iter() {
                all_zero = all_zero & l.is_eq(&zero)?;
            }
            all_zero.enforce_equal(&Boolean::FALSE)?;
        }

        // witness: quotient, rem 은 off-circuit(BigNat)로 계산하여 회로에서는 관계식으로만 검증
        let left_value = self.value.clone();
        let right_value = other.value.clone();
        let mod_value = modulus.value.clone();

        let (quotient_value, rem_value) = if mod_value.is_zero() {
            (BigNat::zero(), BigNat::zero())
        } else {
            let prod = &left_value * &right_value;
            (&prod / &mod_value, &prod % &mod_value)
        };

        let rem = Self::new_witness(cs.clone(), || Ok(rem_value.clone()))?;
        rem.enforce_limb_range_via_bits()?;

        // quotient는 일반적으로 최대 2N limb까지 필요할 수 있어 2N으로 잡아 안전하게 수용
        let num_quotient_limbs: usize = 2 * P::N_LIMBS;
        let mut quotient_value_limbs = fit_nat_to_limbs(&quotient_value, P::LIMB_WIDTH);
        quotient_value_limbs.resize(num_quotient_limbs, ConstraintF::zero());
        let quotient_limbs =
            Vec::<FpVar<ConstraintF>>::new_witness(cs.clone(), || Ok(&quotient_value_limbs[..]))?;
        for q in quotient_limbs.iter() {
            let _ = q.to_bits_le_with_top_bits_zero(P::LIMB_WIDTH)?;
        }
        let quotient = BigNatVar::<ConstraintF, P> {
            limbs: quotient_limbs,
            value: quotient_value.clone(),
            word_size: (BigNat::one() << P::LIMB_WIDTH as u32) - BigNat::one(),
            _params: PhantomData,
        };

        // STRICT: rem < modulus 를 강제하여 "나머지 표현"의 유일성을 확보
        Self::enforce_lt_strict_borrow_chain(cs.clone(), &rem, modulus)?;

        let lr_len = 2 * P::N_LIMBS - 1;
        let mut lr_prod_limbs = vec![FpVar::<ConstraintF>::zero(); lr_len];
        for i in 0..P::N_LIMBS {
            for j in 0..P::N_LIMBS {
                lr_prod_limbs[i + j] += &self.limbs[i] * &other.limbs[j];
            }
        }

        let mq_len = P::N_LIMBS + (2 * P::N_LIMBS) - 1;
        let mut mq_prod_limbs = vec![FpVar::<ConstraintF>::zero(); mq_len];
        for i in 0..P::N_LIMBS {
            for j in 0..(2 * P::N_LIMBS) {
                mq_prod_limbs[i + j] += &modulus.limbs[i] * &quotient.limbs[j];
            }
        }

        let eq_len = core::cmp::max(lr_len, mq_len);
        let mut lhs_limbs = vec![FpVar::<ConstraintF>::zero(); eq_len];
        for i in 0..lr_len {
            lhs_limbs[i] += &lr_prod_limbs[i];
        }
        let mut rhs_limbs = vec![FpVar::<ConstraintF>::zero(); eq_len];
        for i in 0..mq_len {
            rhs_limbs[i] += &mq_prod_limbs[i];
        }
        for i in 0..P::N_LIMBS {
            rhs_limbs[i] += &rem.limbs[i];
        }

        // lhs/rhs limb 배열 구성 후 carry 허용 등식으로
        // self*other == modulus*quotient + rem
        // 을 강제 (carry는 내부에서 witness로 전파)
        let lhs_word_size = BigNat::from(P::N_LIMBS) * &self.word_size * &other.word_size;
        let rhs_word_size =
            BigNat::from(P::N_LIMBS) * &modulus.word_size * &quotient.word_size + &rem.word_size;
        let eq_word_size = max(lhs_word_size, rhs_word_size);

        Self::conditional_enforce_limbs_equal_when_carried(
            cs.clone(),
            &lhs_limbs,
            &rhs_limbs,
            &eq_word_size,
            &Boolean::TRUE,
        )?;
        Ok(rem)
    }

    /// (unchecked) 모듈러 곱셈: 입력 range-check를 생략하는 fast-path
    /// - Unchecked의 의미는 "입력 limb range-check 생략"이며, 출력(rem)과 내부 witness(quotient)는
    ///   관계식 검증을 위해 필요한 최소한의 range-check만 수행합니다.
    /// - ⚠️ 이 구현은 RSA2048 signature verify 최적화를 염두에 둔 경로입니다.
    /// - 특히 quotient limb 수를 `num_quotient_limbs = N`으로 고정합니다.
    ///   (RSA 경로에서는 operand들이 modulus보다 작게 유지되는 구조라 quotient가 상대적으로 작아지는 전제를 사용해 제약조건을 줄이기 위함)
    fn mult_mod_unchecked_impl(
        &self,
        other: &Self,
        modulus: &Self,
    ) -> Result<Self, SynthesisError> {
        let cs = self.cs().or(other.cs()).or(modulus.cs());

        let left_value = self.value.clone();
        let right_value = other.value.clone();
        let mod_value = modulus.value.clone();
        let (quotient_value, rem_value) = if mod_value.is_zero() {
            (BigNat::zero(), BigNat::zero())
        } else {
            let prod = &left_value * &right_value;
            (&prod / &mod_value, &prod % &mod_value)
        };

        // rem을 witness로 두고 canonical(range-check) 강제: rem < 2^w 형태 보장
        let rem = Self::new_witness(cs.clone(), || Ok(rem_value.clone()))?;
        rem.enforce_limb_range_via_bits()?;

        // RSA2048 verify 최적화: quotient limb 수를 N으로 유지(고정)
        let num_quotient_limbs: usize = P::N_LIMBS;
        let mut quotient_value_limbs = fit_nat_to_limbs(&quotient_value, P::LIMB_WIDTH);
        quotient_value_limbs.resize(num_quotient_limbs, ConstraintF::zero());
        let quotient_limbs =
            Vec::<FpVar<ConstraintF>>::new_witness(cs.clone(), || Ok(&quotient_value_limbs[..]))?;
        for q in quotient_limbs.iter() {
            let _ = q.to_bits_le_with_top_bits_zero(P::LIMB_WIDTH)?;
        }
        let quotient = BigNatVar::<ConstraintF, P> {
            limbs: quotient_limbs,
            value: quotient_value.clone(),
            word_size: (BigNat::one() << P::LIMB_WIDTH as u32) - BigNat::one(),
            _params: PhantomData,
        };

        // rem < modulus(STRICT) 강제: mod 결과의 유일성/정의 유지
        Self::enforce_lt_strict_borrow_chain(cs.clone(), &rem, modulus)?;

        let lr_len = 2 * P::N_LIMBS - 1;
        let mut lr_prod_limbs = vec![FpVar::<ConstraintF>::zero(); lr_len];
        for i in 0..P::N_LIMBS {
            for j in 0..P::N_LIMBS {
                lr_prod_limbs[i + j] += &self.limbs[i] * &other.limbs[j];
            }
        }

        let mq_len = P::N_LIMBS + num_quotient_limbs - 1;
        let mut mq_prod_limbs = vec![FpVar::<ConstraintF>::zero(); mq_len];
        for i in 0..P::N_LIMBS {
            for j in 0..num_quotient_limbs {
                mq_prod_limbs[i + j] += &modulus.limbs[i] * &quotient.limbs[j];
            }
        }
        let eq_len = core::cmp::max(lr_len, mq_len);
        let mut lhs_limbs = vec![FpVar::<ConstraintF>::zero(); eq_len];
        for i in 0..lr_len {
            lhs_limbs[i] += &lr_prod_limbs[i];
        }
        let mut rhs_limbs = vec![FpVar::<ConstraintF>::zero(); eq_len];
        for i in 0..mq_len {
            rhs_limbs[i] += &mq_prod_limbs[i];
        }
        for i in 0..P::N_LIMBS {
            rhs_limbs[i] += &rem.limbs[i];
        }

        // carry 전파용 상계(word_size): 등식 검증에서 field wrap-around 위험을 피하기 위한 보수적 bound
        let lhs_word_size = BigNat::from(P::N_LIMBS) * &self.word_size * &other.word_size;
        let rhs_word_size =
            BigNat::from(P::N_LIMBS) * &modulus.word_size * &quotient.word_size + &rem.word_size;
        let eq_word_size = max(lhs_word_size, rhs_word_size);

        Self::conditional_enforce_limbs_equal_when_carried(
            cs.clone(),
            &lhs_limbs,
            &rhs_limbs,
            &eq_word_size,
            &Boolean::TRUE,
        )?;

        Ok(rem)
    }

    /// 모듈러 제곱(Checked): 일반 목적(제네릭) 구현
    pub fn square_mod(&self, modulus: &Self) -> Result<Self, SynthesisError> {
        self.square_mod_mode(modulus, RangeMode::Checked)
    }

    /// 모듈러 제곱(Unchecked): RSA2048 signature verify 최적화를 위한 fast-path 엔트리
    pub fn square_mod_unchecked(&self, modulus: &Self) -> Result<Self, SynthesisError> {
        self.square_mod_mode(modulus, RangeMode::Unchecked)
    }

    /// square_mod 통합 엔트리:
    /// - Checked: 제네릭한 안전 구현
    /// - Unchecked: RSA2048 signature verify용 fast-path(입력 range-check만 생략)
    pub fn square_mod_mode(&self, modulus: &Self, mode: RangeMode) -> Result<Self, SynthesisError> {
        self.maybe_enforce_limb_range(mode)?;
        modulus.maybe_enforce_limb_range(mode)?;

        self.square_mod_unchecked_impl(modulus)
    }

    /// (unchecked) 모듈러 제곱: 입력 range-check를 생략하는 fast-path
    /// - Unchecked의 의미는 "입력 limb range-check 생략"이며, 출력(rem)과 내부 witness(quotient)는
    ///   관계식 검증을 위해 필요한 최소한의 range-check만 수행합니다.
    /// - ⚠️ 이 구현은 RSA2048 signature verify 최적화를 염두에 둔 경로입니다.
    /// - 특히 quotient limb 수를 `num_quotient_limbs = N`으로 고정합니다.
    ///   (RSA 경로에서는 operand들이 modulus보다 작게 유지되는 구조라 quotient가 상대적으로 작아지는 전제를 사용해 제약조건을 줄이기 위함)
    fn square_mod_unchecked_impl(&self, modulus: &Self) -> Result<Self, SynthesisError> {
        let cs = self.cs().or(modulus.cs());

        let left_value = self.value.clone();
        let mod_value = modulus.value.clone();

        let (quotient_value, rem_value) = if mod_value.is_zero() {
            (BigNat::zero(), BigNat::zero())
        } else {
            let prod = &left_value * &left_value;
            (&prod / &mod_value, &prod % &mod_value)
        };

        // rem을 witness로 두고 canonical(range-check) 강제: rem < 2^w 형태 보장
        let rem = Self::new_witness(cs.clone(), || Ok(rem_value.clone()))?;
        rem.enforce_limb_range_via_bits()?;

        // RSA2048 verify 최적화: quotient limb 수를 N으로 유지(고정)
        let num_quotient_limbs: usize = P::N_LIMBS;
        let mut quotient_value_limbs = fit_nat_to_limbs(&quotient_value, P::LIMB_WIDTH);
        quotient_value_limbs.resize(num_quotient_limbs, ConstraintF::zero());
        let quotient_limbs =
            Vec::<FpVar<ConstraintF>>::new_witness(cs.clone(), || Ok(&quotient_value_limbs[..]))?;
        for q in quotient_limbs.iter() {
            let _ = q.to_bits_le_with_top_bits_zero(P::LIMB_WIDTH)?;
        }
        let quotient = BigNatVar::<ConstraintF, P> {
            limbs: quotient_limbs,
            value: quotient_value.clone(),
            word_size: (BigNat::one() << P::LIMB_WIDTH as u32) - BigNat::one(),
            _params: PhantomData,
        };

        // rem < modulus(STRICT) 강제: mod 결과의 유일성/정의 유지
        Self::enforce_lt_strict_borrow_chain(cs.clone(), &rem, modulus)?;

        // lr_prod_limbs: self*self의 limb-wise 누산
        // - i<=j만 계산하고 i!=j는 2배하여 곱셈 항 수를 줄임(제약 감소)
        let lr_len = 2 * P::N_LIMBS - 1;
        let mut lr_prod_limbs = vec![FpVar::<ConstraintF>::zero(); lr_len];
        for i in 0..P::N_LIMBS {
            for j in i..P::N_LIMBS {
                let k = i + j;
                let term = &self.limbs[i] * &self.limbs[j];
                lr_prod_limbs[k] += &term;
                if i != j {
                    lr_prod_limbs[k] += &term;
                }
            }
        }

        let mq_len = P::N_LIMBS + num_quotient_limbs - 1;
        let mut mq_prod_limbs = vec![FpVar::<ConstraintF>::zero(); mq_len];
        for i in 0..P::N_LIMBS {
            for j in 0..num_quotient_limbs {
                mq_prod_limbs[i + j] += &modulus.limbs[i] * &quotient.limbs[j];
            }
        }

        let eq_len = lr_len;
        let mut lhs_limbs = vec![FpVar::<ConstraintF>::zero(); eq_len];
        for i in 0..lr_len {
            lhs_limbs[i] += &lr_prod_limbs[i];
        }
        let mut rhs_limbs = vec![FpVar::<ConstraintF>::zero(); eq_len];
        for i in 0..mq_len {
            rhs_limbs[i] += &mq_prod_limbs[i];
        }
        for i in 0..P::N_LIMBS {
            rhs_limbs[i] += &rem.limbs[i];
        }

        // carry 전파용 상계(word_size)
        let lhs_word_size = BigNat::from(P::N_LIMBS) * &self.word_size * &self.word_size;
        let rhs_word_size =
            BigNat::from(P::N_LIMBS) * &modulus.word_size * &quotient.word_size + &rem.word_size;
        let eq_word_size = max(lhs_word_size, rhs_word_size);

        Self::conditional_enforce_limbs_equal_when_carried(
            cs.clone(),
            &lhs_limbs,
            &rhs_limbs,
            &eq_word_size,
            &Boolean::TRUE,
        )?;

        Ok(rem)
    }

    /// 모듈러 거듭제곱(Checked): 일반 목적(제네릭) 구현
    pub fn pow_mod(
        &self,
        exp: &Self,
        modulus: &Self,
        num_exp_bits: usize,
    ) -> Result<Self, SynthesisError> {
        self.pow_mod_mode(exp, modulus, num_exp_bits, RangeMode::Checked)
    }

    /// 모듈러 거듭제곱(Unchecked): RSA2048 signature verify 최적화를 위한 fast-path 엔트리
    pub fn pow_mod_unchecked(
        &self,
        exp: &Self,
        modulus: &Self,
        num_exp_bits: usize,
    ) -> Result<Self, SynthesisError> {
        self.pow_mod_mode(exp, modulus, num_exp_bits, RangeMode::Unchecked)
    }

    pub fn pow_mod_mode(
        &self,
        exp: &Self,
        modulus: &Self,
        num_exp_bits: usize,
        mode: RangeMode,
    ) -> Result<Self, SynthesisError> {
        // ✅ Unchecked = 입력 range-check만 생략
        self.maybe_enforce_limb_range(mode)?;
        exp.maybe_enforce_limb_range(mode)?;
        modulus.maybe_enforce_limb_range(mode)?;

        // exp limb 표현이 너무 큰 word_size를 갖고 있으면 normalize (기존 로직 유지)
        if exp.word_size >= (BigNat::one() << P::LIMB_WIDTH as u32) {
            // reduce는 "checked 성격"이지만, 이 분기는 exp.word_size가 비정상적으로 큰 경우라
            // 그대로 유지하는 편이 안전합니다.
            return self.pow_mod_mode(&exp.reduce()?, modulus, num_exp_bits, mode);
        }

        let cs = self.cs().or(exp.cs()).or(modulus.cs());

        // ✅ exp 상위비트 0 강제는 soundness 핵심이므로 유지 (mode와 무관)
        let exp_bits = exp.enforce_fits_in_bits(num_exp_bits)?;

        let window_size = if num_exp_bits < 8 {
            1
        } else if num_exp_bits < 32 {
            2
        } else if num_exp_bits < 128 {
            3
        } else if num_exp_bits < 512 {
            4
        } else if num_exp_bits < 2048 {
            5
        } else {
            6
        };

        // ✅ base_powers는 반드시 STRICT rem < modulus를 보장해야 함.
        // Unchecked에서도 mult_mod_checked_impl을 사용 (range-check만 생략)
        let base_powers = {
            let mut base_powers =
                vec![Self::new_constant(cs.clone(), BigNat::one())?, self.clone()];
            for _ in 2..(1 << window_size) {
                let next = base_powers
                    .last()
                    .unwrap()
                    .mult_mod_checked_impl(self, modulus)?;
                base_powers.push(next);
            }
            base_powers
        };

        Self::bauer_power_helper_mode(
            cs.clone(),
            &base_powers,
            exp_bits.chunks(window_size),
            modulus,
            mode,
        )
    }

    /// (pow_mod 내부) Bauer window 방식 거듭제곱 재귀 헬퍼
    /// - exp 비트를 window로 쪼갠 뒤, 각 chunk에 해당하는 base^k를 선택(select_index)
    /// - 재귀적으로 누적(acc)을 만들고, chunk 길이만큼 square 후 multiply를 수행
    /// - 이 구현에서는 soundness를 위해 mult_mod_checked_impl을 사용(STRICT rem < modulus 유지)
    fn bauer_power_helper_mode(
        cs: impl Into<Namespace<ConstraintF>>,
        base_powers: &[Self],
        mut exp_chunks: std::slice::Chunks<Boolean<ConstraintF>>,
        modulus: &Self,
        mode: RangeMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        if let Some(chunk) = exp_chunks.next() {
            let chunk_len = chunk.len();
            let base_power = select_index(&base_powers[..(1 << chunk_len)], chunk)?;

            if exp_chunks.len() > 0 {
                let mut acc = Self::bauer_power_helper_mode(
                    cs.clone(),
                    base_powers,
                    exp_chunks,
                    modulus,
                    mode,
                )?;

                // square step: chunk_len번 제곱 (acc = acc^(2^{chunk_len}))
                for _ in 0..chunk_len {
                    // Unchecked에서도 checked_impl만 사용 (정의 유지)
                    acc = acc.mult_mod_checked_impl(&acc, modulus)?;
                }

                // multiply step: 선택된 base_power를 곱해 다음 상태로 진행
                Ok(acc.mult_mod_checked_impl(&base_power, modulus)?)
            } else {
                Ok(base_power)
            }
        } else {
            Ok(Self::new_constant(cs.clone(), BigNat::one())?)
        }
    }

    /// limb를 여러 개 묶어 “그룹 limb”로 결합하는 유틸
    /// - carry 전파 검증에서 그룹 단위로 처리하면 제약을 줄일 수 있음
    fn group_limbs(
        limbs: &Vec<FpVar<ConstraintF>>,
        limbs_per_group: usize,
    ) -> Vec<FpVar<ConstraintF>> {
        let mut grouped_limbs = vec![];
        let limb_block =
            <FpVar<ConstraintF>>::constant(nat_to_fe(&(BigNat::one() << (P::LIMB_WIDTH as u32))));
        for limbs_to_group in limbs.as_slice().chunks(limbs_per_group) {
            let mut shift = <FpVar<ConstraintF>>::one();
            let mut grouped_limb = <FpVar<ConstraintF>>::zero();
            for limb in limbs_to_group.iter() {
                grouped_limb += &(limb * shift.clone());
                shift *= &limb_block;
            }
            grouped_limbs.push(grouped_limb);
        }
        grouped_limbs
    }

    /// carry를 고려한 동등성 강제 (무조건 검증)
    /// limb 간 carry 전파를 허용하며 두 BigNat이 같은 값을 나타내는지 검증
    pub fn enforce_equal_when_carried(&self, other: &Self) -> Result<(), SynthesisError> {
        let cs = self.cs().or(other.cs());
        let current_word_size = max(&self.word_size, &other.word_size);
        Self::conditional_enforce_limbs_equal_when_carried(
            cs,
            &self.limbs,
            &other.limbs,
            current_word_size,
            &Boolean::TRUE,
        )
    }

    /// condition에 따라 carry를 고려한 동등성 강제
    /// condition이 TRUE일 때만 동등성 검증 수행
    pub fn conditional_enforce_equal_when_carried(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let cs = self.cs().or(other.cs());
        let current_word_size = max(&self.word_size, &other.word_size);
        Self::conditional_enforce_limbs_equal_when_carried(
            cs,
            &self.limbs,
            &other.limbs,
            current_word_size,
            condition,
        )
    }

    /// limb 배열에 대해 carry 전파를 고려한 동등성 강제 (내부 헬퍼)
    /// left_limbs와 right_limbs가 carry를 고려했을 때 동일한 값을 나타내는지 검증
    /// current_word_size: 각 limb의 최대 가능 값 (carry bound 계산에 사용)
    fn conditional_enforce_limbs_equal_when_carried(
        cs: impl Into<Namespace<ConstraintF>>,
        left_limbs: &Vec<FpVar<ConstraintF>>,
        right_limbs: &Vec<FpVar<ConstraintF>>,
        current_word_size: &BigNat,
        condition: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        assert_eq!(left_limbs.len(), right_limbs.len());
        assert!(
            current_word_size.clone() < BigNat::one() << (ConstraintF::MODULUS_BIT_SIZE - 1u32)
        );

        let ns = cs.into();
        let cs = ns.cs();

        // Carry bound: we need carry < 2^carry_bits.
        // Use an integer-only formula to avoid floating-point rounding issues.
        let carry_bits = (current_word_size.bits() as usize)
            .saturating_add(1)
            .saturating_sub(P::LIMB_WIDTH);

        let limbs_per_group =
            ((ConstraintF::MODULUS_BIT_SIZE - 1u32) as usize - carry_bits) / P::LIMB_WIDTH;

        assert!(limbs_per_group >= 1, "limbs_per_group must be >= 1");

        let grouped_base = BigNat::one() << (P::LIMB_WIDTH * limbs_per_group) as u32;
        let grouped_word_size = (0..limbs_per_group).fold(BigNat::ZERO, |mut acc, i| {
            acc.set_bit((i * P::LIMB_WIDTH) as u64, true);
            acc
        }) * current_word_size.clone();

        let grouped_carry_bits =
            (grouped_word_size.bits() as usize - P::LIMB_WIDTH * limbs_per_group + 1) as usize;

        // Propagate carries over grouped limbs.
        let mut carry_in = FpVar::<ConstraintF>::Constant(ConstraintF::ZERO);
        let mut accumulated_extra = BigNat::ZERO;

        // Group limbs once (avoid recomputation) and iterate over groups.
        let left_grouped = Self::group_limbs(left_limbs, limbs_per_group);
        let right_grouped = Self::group_limbs(right_limbs, limbs_per_group);

        for (i, (left_limb, right_limb)) in
            left_grouped.iter().zip(right_grouped.iter()).enumerate()
        {
            let left_limb_value = left_limb.value().unwrap_or_default();
            let right_limb_value = right_limb.value().unwrap_or_default();
            let carry_in_value = carry_in.value().unwrap_or_default();

            let carry_value = nat_to_fe::<ConstraintF>(
                &((fe_to_nat(&left_limb_value)
                    + fe_to_nat(&carry_in_value)
                    + grouped_word_size.clone()
                    - fe_to_nat(&right_limb_value))
                    / grouped_base.clone()),
            );

            let carry = <FpVar<ConstraintF>>::new_witness(cs.clone(), || Ok(carry_value))?;

            accumulated_extra += grouped_word_size.clone();

            let (tmp_accumulated_extra, remainder) = accumulated_extra.div_rem(&grouped_base);
            accumulated_extra = tmp_accumulated_extra;
            let remainder_limb = nat_to_fe::<ConstraintF>(&remainder);

            let eqn_left: FpVar<ConstraintF> =
                left_limb + &carry_in - right_limb + nat_to_fe::<ConstraintF>(&grouped_word_size);
            let eqn_right = &carry * nat_to_fe::<ConstraintF>(&grouped_base) + remainder_limb;

            eqn_left.conditional_enforce_equal(&eqn_right, condition)?;

            // last-iteration check must be based on number of GROUPS, not raw limb length.
            if i + 1 < left_grouped.len() {
                Self::conditional_enforce_limb_fits_in_bits(&carry, grouped_carry_bits, condition)?;
            } else {
                carry.conditional_enforce_equal(
                    &FpVar::<ConstraintF>::Constant(nat_to_fe::<ConstraintF>(&accumulated_extra)),
                    condition,
                )?;
            }

            carry_in = carry.clone();
        }

        Ok(())
    }

    /// BigNat이 n_bits 이하의 비트 수로 표현 가능한지 강제하고 비트 배열 반환
    /// 상위 limb들은 0이어야 하며, 최상위 non-zero limb는 n_bits % LIMB_WIDTH 비트 이하
    pub fn enforce_fits_in_bits(
        &self,
        n_bits: usize,
    ) -> Result<Vec<Boolean<ConstraintF>>, SynthesisError> {
        let mut bit_vars = vec![];
        let num_limbs = n_bits / P::LIMB_WIDTH;
        for (i, limb) in self.limbs.iter().enumerate() {
            if i < num_limbs {
                bit_vars.append(&mut Self::enforce_limb_fits_in_bits(limb, P::LIMB_WIDTH)?);
            } else if i == num_limbs {
                bit_vars.append(&mut Self::enforce_limb_fits_in_bits(
                    limb,
                    n_bits % P::LIMB_WIDTH,
                )?);
            } else {
                limb.enforce_equal(&<FpVar<ConstraintF>>::zero())?;
            }
        }
        Ok(bit_vars)
    }

    /// 단일 limb가 n_bits 이하로 표현 가능한지 강제 (무조건 검증)
    pub fn enforce_limb_fits_in_bits(
        limb: &FpVar<ConstraintF>,
        n_bits: usize,
    ) -> Result<Vec<Boolean<ConstraintF>>, SynthesisError> {
        Self::conditional_enforce_limb_fits_in_bits(limb, n_bits, &Boolean::TRUE)
    }

    /// condition에 따라 단일 limb가 n_bits 이하로 표현 가능한지 강제
    /// field wrap-around 방지를 위해 modulus bit size - 1로 상한 제한
    fn conditional_enforce_limb_fits_in_bits(
        limb: &FpVar<ConstraintF>,
        n_bits: usize,
        condition: &Boolean<ConstraintF>,
    ) -> Result<Vec<Boolean<ConstraintF>>, SynthesisError> {
        let cs = limb.cs();

        // field wrap-around 회피를 위해 modulus bit size - 1로 상한
        let n_bits = core::cmp::min(ConstraintF::MODULUS_BIT_SIZE as usize - 1, n_bits);

        // ✅ BigInt "표현(repr)"의 전체 비트 길이 (버전 독립)
        let repr_bits = core::mem::size_of::<<ConstraintF as PrimeField>::BigInt>() * 8;

        let limb_value = limb.value().unwrap_or_default();

        // BitIteratorBE는 repr_bits 전부(=shaved bits 포함)를 순회하므로,
        // 최하위 n_bits만 취하기 위해 상위 repr_bits - n_bits를 skip
        let skip = repr_bits.saturating_sub(n_bits);

        let mut bits_be = Vec::with_capacity(n_bits);
        for b in BitIteratorBE::new(limb_value.into_bigint()).skip(skip) {
            bits_be.push(b);
        }

        // 기존 코드가 bits.iter().rev()로 LE witness를 만들었으므로 동일 유지
        let mut bit_vars = Vec::with_capacity(n_bits);
        if cs != ConstraintSystemRef::None {
            for b in bits_be.iter().rev() {
                bit_vars.push(Boolean::<ConstraintF>::new_witness(cs.clone(), || Ok(*b))?);
            }
            Self::conditional_enforce_limb_equals_bits(limb, &bit_vars, condition)?;
        } else {
            for b in bits_be.iter().rev() {
                bit_vars.push(Boolean::<ConstraintF>::constant(*b));
            }
        }

        Ok(bit_vars)
    }

    /// BigNat이 주어진 비트 배열과 동일한지 강제 (무조건 검증)
    pub fn enforce_equals_bits(&self, bits: &[Boolean<ConstraintF>]) -> Result<(), SynthesisError> {
        self.conditional_enforce_equals_bits(bits, &Boolean::TRUE)
    }

    /// condition에 따라 BigNat이 주어진 비트 배열과 동일한지 강제
    pub fn conditional_enforce_equals_bits(
        &self,
        bits: &[Boolean<ConstraintF>],
        condition: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let num_nonzero_limbs = bits.len() / P::LIMB_WIDTH;

        for (i, limb) in self.limbs.iter().enumerate() {
            if i < num_nonzero_limbs {
                Self::conditional_enforce_limb_equals_bits(
                    limb,
                    &bits[i * P::LIMB_WIDTH..(i + 1) * P::LIMB_WIDTH],
                    condition,
                )?;
            } else if i == num_nonzero_limbs {
                Self::conditional_enforce_limb_equals_bits(
                    limb,
                    &bits[i * P::LIMB_WIDTH..],
                    condition,
                )?;
            } else {
                limb.conditional_enforce_equal(&<FpVar<ConstraintF>>::zero(), condition)?;
            }
        }
        Ok(())
    }

    /// condition에 따라 단일 limb가 주어진 비트 배열과 동일한지 강제 (내부 헬퍼)
    fn conditional_enforce_limb_equals_bits(
        limb: &FpVar<ConstraintF>,
        bits: &[Boolean<ConstraintF>],
        condition: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let cs = limb.cs();
        if cs != ConstraintSystemRef::None {
            limb.conditional_enforce_equal(&Self::limb_from_bits(bits)?, condition)?;
        }
        Ok(())
    }

    /// 비트 배열로부터 단일 limb (FpVar) 생성
    /// 리틀 엔디안 순서로 비트를 조합하여 field element 생성
    pub fn limb_from_bits(
        bits: &[Boolean<ConstraintF>],
    ) -> Result<FpVar<ConstraintF>, SynthesisError> {
        let mut bit_sum = FpVar::<ConstraintF>::zero();
        let mut coeff = ConstraintF::one();
        for bit in bits.iter() {
            bit_sum +=
                <FpVar<ConstraintF> as From<Boolean<ConstraintF>>>::from((*bit).clone()) * coeff;
            coeff.double_in_place();
        }
        Ok(bit_sum)
    }

    /// 모든 limb가 LIMB_WIDTH 비트 이하로 표현 가능한지 range check
    /// 각 limb를 비트 분해하여 범위 강제 (canonical 형태 보장)
    pub fn enforce_limb_range_via_bits(&self) -> Result<(), SynthesisError> {
        for limb in self.limbs.iter() {
            let _ = limb.to_bits_le_with_top_bits_zero(P::LIMB_WIDTH)?;
        }
        Ok(())
    }

    pub fn enforce_lt_strict_borrow_chain(
        cs: ConstraintSystemRef<ConstraintF>,
        a: &BigNatVar<ConstraintF, P>,
        b: &BigNatVar<ConstraintF, P>,
    ) -> Result<(), SynthesisError> {
        // a,b are assumed canonical (limb < 2^w). Caller ensured at allocation time.

        // Base B = 2^LIMB_WIDTH (works even when LIMB_WIDTH >= 64)
        let base_const = ConstraintF::from(2u64).pow([P::LIMB_WIDTH as u64]);
        let base = FpVar::<ConstraintF>::constant(base_const);

        // mask = (1<<w)-1 in BigNat
        let mask = (BigNat::one() << (P::LIMB_WIDTH as u32)) - BigNat::one();

        // Compute diff = b - a and borrow_out[i] off-circuit (per limb)
        // If b < a, we still produce something, but final borrow will force failure.
        let mut borrow_bits: Vec<bool> = Vec::with_capacity(P::N_LIMBS);
        let mut diff_limbs_nat: Vec<BigNat> = Vec::with_capacity(P::N_LIMBS);

        let mut borrow: bool = false;
        for i in 0..P::N_LIMBS {
            let shift = (i * P::LIMB_WIDTH) as u32;

            let a_i = (&a.value >> shift) & &mask;
            let b_i = (&b.value >> shift) & &mask;

            // compute: b_i - a_i - borrow
            // if underflow at this limb => borrow_out = 1 and add base
            let (d_i, borrow_out) = if !borrow {
                if b_i >= a_i {
                    (b_i.clone() - a_i, false)
                } else {
                    ((b_i + (&mask + BigNat::one())) - a_i, true) // +B - a_i
                }
            } else {
                // subtract 1 extra
                if b_i > a_i {
                    (b_i.clone() - a_i - BigNat::one(), false)
                } else if b_i == a_i {
                    ((&mask + BigNat::one()) - BigNat::one(), true) // B-1, borrow continues
                } else {
                    ((b_i + (&mask + BigNat::one())) - a_i - BigNat::one(), true)
                }
            };

            diff_limbs_nat.push(d_i);
            borrow_bits.push(borrow_out);
            borrow = borrow_out;
        }

        // Allocate diff limbs
        let mut diff_limbs_val = diff_limbs_nat
            .iter()
            .map(|x| nat_to_fe::<ConstraintF>(x))
            .collect::<Vec<_>>();
        diff_limbs_val.resize(P::N_LIMBS, ConstraintF::zero());
        let diff_limbs =
            Vec::<FpVar<ConstraintF>>::new_witness(cs.clone(), || Ok(&diff_limbs_val[..]))?;

        // Enforce borrow-chain and strictness
        let mut borrow_prev = FpVar::<ConstraintF>::zero();
        let mut any_nonzero = Boolean::<ConstraintF>::FALSE;

        for i in 0..P::N_LIMBS {
            // range-check diff limb (needed to make limb meaning sound)
            let _ = diff_limbs[i].to_bits_le_with_top_bits_zero(P::LIMB_WIDTH)?;

            // witness borrow_out[i]
            let bi = borrow_bits[i];
            let borrow_out = Boolean::<ConstraintF>::new_witness(cs.clone(), || Ok(bi))?;
            let borrow_out_fp =
                borrow_out.select(&FpVar::<ConstraintF>::one(), &FpVar::<ConstraintF>::zero())?;

            // (b_i - a_i - borrow_prev) + borrow_out*B - diff_i == 0
            let lhs =
                &b.limbs[i] - &a.limbs[i] - &borrow_prev + &borrow_out_fp * &base - &diff_limbs[i];
            lhs.enforce_equal(&FpVar::<ConstraintF>::zero())?;

            // diff != 0  (strict)
            let limb_is_nonzero = diff_limbs[i].is_neq(&FpVar::<ConstraintF>::zero())?;
            any_nonzero = any_nonzero | limb_is_nonzero;

            borrow_prev = borrow_out_fp;
        }

        // final borrow must be 0  => a <= b
        borrow_prev.enforce_equal(&FpVar::<ConstraintF>::zero())?;

        // strict: diff != 0 => a != b
        any_nonzero.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

impl<ConstraintF: PrimeField, P: BigNatCircuitParams> CondSelectGadget<ConstraintF>
    for BigNatVar<ConstraintF, P>
{
    fn conditionally_select(
        cond: &Boolean<ConstraintF>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let selected_limbs = true_value
            .limbs
            .iter()
            .zip(&false_value.limbs)
            .map(|(true_limb, false_limb)| cond.select(true_limb, false_limb))
            .collect::<Result<Vec<FpVar<ConstraintF>>, SynthesisError>>()?;
        let cond_bool = cond.value().unwrap_or_default();
        let selected_nat = if cond_bool { true_value } else { false_value };
        Ok(Self {
            limbs: selected_limbs,
            value: selected_nat.value.clone(),
            word_size: max(true_value.word_size.clone(), false_value.word_size.clone()),
            _params: PhantomData,
        })
    }
}

impl<ConstraintF: PrimeField, P: BigNatCircuitParams> EqGadget<ConstraintF>
    for BigNatVar<ConstraintF, P>
{
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF>, SynthesisError> {
        self.limbs.is_eq(&other.limbs)
    }
}

pub fn log2(x: usize) -> u32 {
    if x == 0 {
        0
    } else if x.is_power_of_two() {
        1usize.leading_zeros() - x.leading_zeros()
    } else {
        0usize.leading_zeros() - x.leading_zeros()
    }
}

pub fn select_index<ConstraintF: PrimeField, T: CondSelectGadget<ConstraintF>>(
    v: &[T],
    index_bits: &[Boolean<ConstraintF>],
) -> Result<T, SynthesisError> {
    debug_assert!(index_bits.len() > 0);
    if index_bits.len() == 1 {
        assert_eq!(v.len(), 2);
        T::conditionally_select(&index_bits[0], &v[1], &v[0])
    } else {
        let left = select_index(&v[..(v.len() / 2)], &index_bits[..(index_bits.len() - 1)])?;
        let right = select_index(&v[(v.len() / 2)..], &index_bits[..(index_bits.len() - 1)])?;
        T::conditionally_select(&index_bits.last().unwrap(), &right, &left)
    }
}

impl<ConstraintF: PrimeField, P: BigNatCircuitParams> ToBytesGadget<ConstraintF>
    for BigNatVar<ConstraintF, P>
{
    fn to_bytes_le(&self) -> Result<Vec<UInt8<ConstraintF>>, SynthesisError> {
        let mut bits = self.enforce_fits_in_bits(P::LIMB_WIDTH * P::N_LIMBS)?;
        bits.resize((((bits.len() - 1) / 8) + 1) * 8, Boolean::FALSE);
        Ok(bits
            .chunks(8)
            .map(|byte| UInt8::from_bits_le(byte))
            .collect::<Vec<UInt8<ConstraintF>>>())
    }
}
pub trait BigNatTrait<ConstraintF: PrimeField, P: BigNatCircuitParams> {
    fn alloc_from_u64_limbs(
        cs: impl Into<Namespace<ConstraintF>>,
        u64_limbs: &Vec<u64>,
        word_size: BigNat,
        mode: AllocationMode,
    ) -> Result<BigNatVar<ConstraintF, P>, SynthesisError>;

    fn alloc_from_limbs(
        cs: impl Into<Namespace<ConstraintF>>,
        limbs: &Vec<ConstraintF>,
        word_size: BigNat,
        mode: AllocationMode,
    ) -> Result<BigNatVar<ConstraintF, P>, SynthesisError>;
}

impl<ConstraintF: PrimeField, P: BigNatCircuitParams> BigNatTrait<ConstraintF, P>
    for BigNatVar<ConstraintF, P>
{
    fn alloc_from_u64_limbs(
        cs: impl Into<Namespace<ConstraintF>>,
        u64_limbs: &Vec<u64>,
        word_size: BigNat,
        mode: AllocationMode,
    ) -> Result<BigNatVar<ConstraintF, P>, SynthesisError> {
        let limbs = u64_limbs
            .iter()
            .rev()
            .map(|int64| ConstraintF::from_bigint(ConstraintF::BigInt::from(*int64)).unwrap())
            .collect::<Vec<ConstraintF>>();
        Self::alloc_from_limbs(cs, &limbs, word_size, mode)
    }

    fn alloc_from_limbs(
        cs: impl Into<Namespace<ConstraintF>>,
        limbs: &Vec<ConstraintF>,
        word_size: BigNat,
        mode: AllocationMode,
    ) -> Result<BigNatVar<ConstraintF, P>, SynthesisError> {
        assert_eq!(limbs.len(), P::N_LIMBS);
        let limb_vars = Vec::<FpVar<ConstraintF>>::new_variable(cs, || Ok(&limbs[..]), mode)?;
        let result = BigNatVar {
            limbs: limb_vars,
            value: limbs_to_nat::<ConstraintF>(limbs, P::LIMB_WIDTH),
            word_size: word_size,
            _params: PhantomData,
        };
        Ok(result)
    }
}

#[cfg(test)]
mod test {

    use std::io::Write;

    use ark_ed_on_bn254::Fq;
    use ark_relations::r1cs::ConstraintSystem;

    use super::*;

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct BigNatTestParams;

    impl BigNatCircuitParams for BigNatTestParams {
        const LIMB_WIDTH: usize = 3;
        const N_LIMBS: usize = 4;
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct BigNat512TestParams;

    impl BigNatCircuitParams for BigNat512TestParams {
        const LIMB_WIDTH: usize = 32;
        const N_LIMBS: usize = 16;
    }

    #[test]
    fn bignat_to_bytes_test() {
        let bignat = BigNat::from(5000u64);
        let cs = ConstraintSystem::<Fq>::new_ref();
        let bignat_var =
            BigNatVar::<Fq, BigNat512TestParams>::new_witness(cs.clone(), || Ok(&bignat)).unwrap();
        let bytes_val = bignat_var
            .to_bytes_le()
            .unwrap()
            .iter()
            .map(|b| b.value().unwrap())
            .collect::<Vec<u8>>();
        assert_eq!(bytes_val.len(), 64);
        let mut buffer = [0u8; 64];
        let mut writer = std::io::Cursor::new(&mut buffer[..]);
        let big_vec = bignat.to_bytes_le();
        writer.write_all(&big_vec).unwrap();
        assert_eq!(bytes_val, buffer.to_vec());
    }

    fn carry_over_equal_test(
        vec1: Vec<u64>,
        vec2: Vec<u64>,
        word_size_1: u64,
        word_size_2: u64,
        should_satisfy: bool,
    ) {
        println!("vec1: {:?}, vec2: {:?}", vec1.clone(), vec2.clone());
        let cs = ConstraintSystem::<Fq>::new_ref();
        let nat1var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat1"),
            &vec1,
            BigNat::from(word_size_1),
            AllocationMode::Witness,
        )
        .unwrap();
        let nat2var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat2"),
            &vec2,
            BigNat::from(word_size_2),
            AllocationMode::Witness,
        )
        .unwrap();
        nat1var.enforce_equal_when_carried(&nat2var).unwrap();

        if should_satisfy && !cs.is_satisfied().unwrap() {
            println!("=========================================================");
            println!("Unsatisfied constraints:");
            println!("{}", cs.which_is_unsatisfied().unwrap().unwrap());
            println!("=========================================================");
        }
        assert_eq!(should_satisfy, cs.is_satisfied().unwrap());
    }

    #[test]
    fn carry_over_equal_trivial_test() {
        carry_over_equal_test(vec![2, 1, 4, 7], vec![2, 1, 4, 7], 7, 7, true)
    }

    #[test]
    fn carry_over_equal_1carry_test() {
        carry_over_equal_test(vec![1, 1, 0, 9], vec![1, 1, 1, 1], 14, 7, true)
    }

    #[test]
    fn carry_over_equal_2carry_test() {
        carry_over_equal_test(vec![1, 1, 9, 9], vec![1, 2, 2, 1], 14, 7, true)
    }

    #[test]
    fn carry_over_equal_both_carry_test() {
        carry_over_equal_test(vec![1, 1, 9, 9], vec![1, 0, 18, 1], 14, 21, true)
    }

    #[test]
    fn carry_over_equal_large_word_test() {
        carry_over_equal_test(vec![1, 1, 9, 66], vec![1, 3, 1, 2], 70, 7, true)
    }

    #[test]
    fn carry_over_equal_3carry_test() {
        carry_over_equal_test(vec![1, 12, 7, 12], vec![2, 5, 0, 4], 14, 7, true)
    }

    #[test]
    fn carry_over_equal_3carry_overflow_test() {
        carry_over_equal_test(vec![12, 12, 12, 12], vec![13, 5, 5, 4], 14, 14, true)
    }

    fn add_equal_test(
        vec1: Vec<u64>,
        vec2: Vec<u64>,
        vec3: Vec<u64>,
        word_size_1: u64,
        word_size_2: u64,
        word_size_3: u64,
        should_satisfy: bool,
    ) {
        println!("vec1: {:?}, vec2: {:?}", vec1.clone(), vec2.clone());
        let cs = ConstraintSystem::<Fq>::new_ref();
        let nat1var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat1"),
            &vec1,
            BigNat::from(word_size_1),
            AllocationMode::Witness,
        )
        .unwrap();
        let nat2var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat2"),
            &vec2,
            BigNat::from(word_size_2),
            AllocationMode::Witness,
        )
        .unwrap();
        let nat3var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat3"),
            &vec3,
            BigNat::from(word_size_3),
            AllocationMode::Witness,
        )
        .unwrap();

        let sum = nat1var.add(&nat2var).unwrap();
        nat3var.enforce_equal_when_carried(&sum).unwrap();

        if should_satisfy && !cs.is_satisfied().unwrap() {
            println!("=========================================================");
            println!("Unsatisfied constraints:");
            println!("{}", cs.which_is_unsatisfied().unwrap().unwrap());
            println!("=========================================================");
        }
        assert_eq!(should_satisfy, cs.is_satisfied().unwrap());
    }

    #[test]
    fn add_equal_trivial_test() {
        add_equal_test(
            vec![1, 1, 1, 1],
            vec![1, 1, 1, 1],
            vec![2, 2, 2, 2],
            7,
            7,
            7,
            true,
        )
    }

    #[test]
    fn add_equal_carryover_test() {
        add_equal_test(
            vec![1, 1, 1, 6],
            vec![1, 1, 1, 6],
            vec![2, 2, 3, 4],
            7,
            7,
            7,
            true,
        )
    }

    fn sub_equal_test(
        vec1: Vec<u64>,
        vec2: Vec<u64>,
        vec3: Vec<u64>,
        word_size_1: u64,
        word_size_2: u64,
        word_size_3: u64,
        should_satisfy: bool,
    ) {
        println!("vec1: {:?}, vec2: {:?}", vec1.clone(), vec2.clone());
        let cs = ConstraintSystem::<Fq>::new_ref();
        let nat1var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat1"),
            &vec1,
            BigNat::from(word_size_1),
            AllocationMode::Witness,
        )
        .unwrap();
        let nat2var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat2"),
            &vec2,
            BigNat::from(word_size_2),
            AllocationMode::Witness,
        )
        .unwrap();
        let nat3var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat3"),
            &vec3,
            BigNat::from(word_size_3),
            AllocationMode::Witness,
        )
        .unwrap();

        let diff = nat1var.sub(&nat2var).unwrap();
        nat3var.enforce_equal_when_carried(&diff).unwrap();

        println!("Number of constraints: {}", cs.num_constraints());
        if should_satisfy && !cs.is_satisfied().unwrap() {
            println!("=========================================================");
            println!("Unsatisfied constraints:");
            println!("{}", cs.which_is_unsatisfied().unwrap().unwrap());
            println!("=========================================================");
        }
        assert_eq!(should_satisfy, cs.is_satisfied().unwrap());
    }

    #[test]
    fn sub_equal_trivial_test() {
        sub_equal_test(
            vec![2, 2, 2, 2],
            vec![1, 1, 1, 1],
            vec![1, 1, 1, 1],
            7,
            7,
            7,
            true,
        )
    }

    #[test]
    fn sub_equal_carryover_test() {
        sub_equal_test(
            vec![2, 0, 18, 2],
            vec![1, 1, 1, 1],
            vec![1, 1, 1, 1],
            21,
            7,
            7,
            true,
        )
    }

    fn mult_mod_test(
        vec1: Vec<u64>,
        vec2: Vec<u64>,
        vec3: Vec<u64>,
        modvec: Vec<u64>,
        word_size_1: u64,
        word_size_2: u64,
        word_size_3: u64,
        mod_word_size: u64,
        should_satisfy: bool,
    ) {
        println!("vec1: {:?}, vec2: {:?}", vec1.clone(), vec2.clone());
        let cs = ConstraintSystem::<Fq>::new_ref();
        let nat1var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat1"),
            &vec1,
            BigNat::from(word_size_1),
            AllocationMode::Witness,
        )
        .unwrap();
        let nat2var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat2"),
            &vec2,
            BigNat::from(word_size_2),
            AllocationMode::Witness,
        )
        .unwrap();
        let nat3var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat3"),
            &vec3,
            BigNat::from(word_size_3),
            AllocationMode::Witness,
        )
        .unwrap();
        let modvar = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "mod"),
            &modvec,
            BigNat::from(mod_word_size),
            AllocationMode::Witness,
        )
        .unwrap();

        let prod = nat1var.mult_mod(&nat2var, &modvar).unwrap();
        nat3var.enforce_equal_when_carried(&prod).unwrap();

        println!("Number of constraints: {}", cs.num_constraints());
        if should_satisfy && !cs.is_satisfied().unwrap() {
            println!("=========================================================");
            println!("Unsatisfied constraints:");
            println!("{}", cs.which_is_unsatisfied().unwrap().unwrap());
            println!("=========================================================");
        }
        assert_eq!(should_satisfy, cs.is_satisfied().unwrap());
    }

    #[test]
    fn mult_mod_trivial_test() {
        mult_mod_test(
            vec![0, 0, 1, 1],
            vec![0, 0, 1, 1],
            vec![0, 1, 2, 1],
            vec![0, 7, 0, 0],
            7,
            7,
            7,
            7,
            true,
        )
    }

    #[test]
    fn mult_mod_prod_overflow_test() {
        mult_mod_test(
            vec![1, 1, 1, 1], // 585
            vec![2, 2, 0, 0], // 1152
            vec![3, 2, 2, 0], // 585 * 1152 = 673920 ; 673920 % 2801 = 1680
            vec![5, 3, 6, 1], // prime mod = 2801
            7,
            7,
            7,
            7,
            true,
        )
    }

    #[test]
    fn mult_mod_large_quotient_test() {
        mult_mod_test(
            vec![65, 1, 1, 1], // 33353
            vec![66, 2, 0, 0], // 33920
            vec![2, 6, 6, 1],  // (33353 * 33920) % 2801 = 1457
            vec![5, 3, 6, 1],  // prime mod = 2801
            70,
            70,
            7,
            7,
            true,
        )
    }

    fn pow_mod_test(
        vec1: Vec<u64>,
        vec2: Vec<u64>,
        vec3: Vec<u64>,
        modvec: Vec<u64>,
        word_size_1: u64,
        word_size_2: u64,
        word_size_3: u64,
        mod_word_size: u64,
        num_exp_bits: usize,
        should_satisfy: bool,
    ) {
        println!("vec1: {:?}, vec2: {:?}", vec1.clone(), vec2.clone());
        let cs = ConstraintSystem::<Fq>::new_ref();
        let nat1var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat1"),
            &vec1,
            BigNat::from(word_size_1),
            AllocationMode::Witness,
        )
        .unwrap();
        println!(
            "vec1: {}",
            limbs_to_nat(
                &nat1var.limbs.value().unwrap(),
                BigNatTestParams::LIMB_WIDTH
            )
        );
        println!("vec1.value: {:?}", nat1var.limbs.value().unwrap());

        let nat2var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat2"),
            &vec2,
            BigNat::from(word_size_2),
            AllocationMode::Witness,
        )
        .unwrap();
        println!(
            "vec2: {}",
            limbs_to_nat(
                &nat2var.limbs.value().unwrap(),
                BigNatTestParams::LIMB_WIDTH
            )
        );
        println!("vec2.value: {:?}", nat2var.limbs.value().unwrap());

        let nat3var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat3"),
            &vec3,
            BigNat::from(word_size_3),
            AllocationMode::Witness,
        )
        .unwrap();
        println!("vec3.value: {:?}", nat3var.limbs.value().unwrap());

        let modvar = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "mod"),
            &modvec,
            BigNat::from(mod_word_size),
            AllocationMode::Witness,
        )
        .unwrap();
        println!(
            "modvar: {}",
            limbs_to_nat(&modvar.limbs.value().unwrap(), BigNatTestParams::LIMB_WIDTH)
        );

        let result = nat1var.pow_mod(&nat2var, &modvar, num_exp_bits).unwrap();
        println!("POW MOD DONE");
        println!(
            "result: {}",
            limbs_to_nat(&result.limbs.value().unwrap(), BigNatTestParams::LIMB_WIDTH)
        );
        println!(
            "expected: {}",
            limbs_to_nat(
                &nat3var.limbs.value().unwrap(),
                BigNatTestParams::LIMB_WIDTH
            )
        );
        nat3var.enforce_equal_when_carried(&result).unwrap();

        println!("Number of constraints: {}", cs.num_constraints());
        if should_satisfy && !cs.is_satisfied().unwrap() {
            println!("=========================================================");
            println!("Unsatisfied constraints:");
            println!("{}", cs.which_is_unsatisfied().unwrap().unwrap());
            println!("=========================================================");
        }
        assert_eq!(should_satisfy, cs.is_satisfied().unwrap());
    }

    #[test]
    fn pow_mod_trivial1_test() {
        pow_mod_test(
            vec![0, 0, 0, 3], // 3
            vec![0, 0, 0, 6], // 6
            vec![1, 3, 3, 1], // 3^6 = 729
            vec![5, 3, 6, 1], // prime mod = 2801
            7,
            7,
            7,
            7,
            3,
            true,
        )
    }

    #[test]
    fn pow_mod_trivial2_test() {
        pow_mod_test(
            vec![0, 0, 0, 3], // 3
            vec![0, 0, 0, 7], // 7
            vec![4, 2, 1, 3], // 3^7 = 2187
            vec![5, 3, 6, 1], // prime mod = 2801
            7,
            7,
            7,
            7,
            4,
            true,
        )
    }

    #[test]
    fn pow_mod_zero_test() {
        pow_mod_test(
            vec![1, 1, 1, 1], // 585
            vec![0, 0, 0, 0],
            vec![0, 0, 0, 1],
            vec![5, 3, 6, 1], // prime mod = 2801
            7,
            7,
            7,
            7,
            3,
            true,
        )
    }

    #[test]
    fn pow_mod_small_overflow_test() {
        pow_mod_test(
            vec![0, 0, 0, 3], // 3
            vec![0, 0, 1, 0], // 8
            vec![1, 6, 7, 7], // 3^8 % 2801 = 959
            vec![5, 3, 6, 1], // prime mod = 2801
            7,
            7,
            7,
            7,
            6,
            true,
        )
    }

    #[test]
    fn pow_mod_full_test() {
        pow_mod_test(
            vec![1, 1, 1, 3], // 587 // 2048 bit의 vec를 만들어주세요
            vec![0, 0, 2, 1], // 17
            vec![0, 5, 7, 0], // (587^17) % 2801 = 376
            vec![5, 3, 6, 1], // prime mod = 2801
            7,
            7,
            7,
            7,
            6,
            true,
        )
    }

    /// BigNat2048TestParams 정의
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct BigNat2048TestParams;

    impl BigNatCircuitParams for BigNat2048TestParams {
        const LIMB_WIDTH: usize = 64;
        const N_LIMBS: usize = 32;
    }

    #[test]
    fn pow_mod_rsa_style_17bit_exp_test() {
        use num_bigint::BigUint;
        use num_traits::One;
        use rand::{RngCore, thread_rng};

        // BigUint를 Big-Endian u64 limb 벡터로 변환하는 헬퍼 함수
        let to_be_limbs = |n: &BigUint| -> Vec<u64> {
            let limb_bytes = BigNat2048TestParams::LIMB_WIDTH / 8;
            let num_bytes = BigNat2048TestParams::N_LIMBS * limb_bytes;
            let bytes = n.to_bytes_be();
            let padding = num_bytes.saturating_sub(bytes.len());
            let mut padded_bytes = vec![0; padding];
            padded_bytes.extend_from_slice(&bytes);
            padded_bytes
                .chunks_exact(limb_bytes)
                .map(|chunk| u64::from_be_bytes(chunk.try_into().unwrap()))
                .collect::<Vec<u64>>()
        };

        // 1. 테스트용 RSA 스타일 값 설정
        let mut rng = thread_rng();

        // Exponent (e = 65537, 17비트)
        let exp_val = BigUint::from(65537u32);
        let num_exp_bits = 17;

        // Base (Message, 2048-bit)
        let mut base_bytes = vec![0u8; 2048 / 8];
        rng.fill_bytes(&mut base_bytes);
        let base_val = BigUint::from_bytes_be(&base_bytes);

        // Modulus (N, 2040-bit, 홀수 보장)
        let mut mod_bytes = vec![0u8; 2040 / 8];
        rng.fill_bytes(&mut mod_bytes);
        // last_mut()으로 마지막 요소를 안전하게 가져와 홀수로 만듭니다.
        if let Some(last_byte) = mod_bytes.last_mut() {
            *last_byte |= 1;
        }
        let mod_val = BigUint::from_bytes_be(&mod_bytes);

        // 2. 예상 결과값 계산 (ciphertext = base^exp % mod)
        let expected_res_val = base_val.modpow(&exp_val, &mod_val);

        // BigUint 값들을 회로 입력에 맞는 limb 벡터로 변환
        let base_limbs = to_be_limbs(&base_val);
        let exp_limbs = to_be_limbs(&exp_val);
        let mod_limbs = to_be_limbs(&mod_val);
        let expected_res_limbs = to_be_limbs(&expected_res_val);

        // 3. 제약 조건 시스템 설정
        let cs = ConstraintSystem::<Fq>::new_ref();
        let word_size: BigNat = (BigNat::one() << 64) - BigNat::one();

        // 4. 회로 변수 할당
        let base_var = BigNatVar::<Fq, BigNat2048TestParams>::alloc_from_u64_limbs(
            cs.clone(),
            &base_limbs,
            word_size.clone(),
            AllocationMode::Witness,
        )
        .unwrap();
        let exp_var = BigNatVar::<Fq, BigNat2048TestParams>::alloc_from_u64_limbs(
            cs.clone(),
            &exp_limbs,
            word_size.clone(),
            AllocationMode::Witness,
        )
        .unwrap();
        let mod_var = BigNatVar::<Fq, BigNat2048TestParams>::alloc_from_u64_limbs(
            cs.clone(),
            &mod_limbs,
            word_size.clone(),
            AllocationMode::Witness,
        )
        .unwrap();
        let expected_res_var = BigNatVar::<Fq, BigNat2048TestParams>::alloc_from_u64_limbs(
            cs.clone(),
            &expected_res_limbs,
            word_size.clone(),
            AllocationMode::Witness,
        )
        .unwrap();

        // 5. 회로 내에서 모듈러 거듭제곱 연산 수행
        let res_var = base_var.pow_mod(&exp_var, &mod_var, num_exp_bits).unwrap();

        // 6. 회로 결과와 예상 결과가 같은지 제약 조건 추가
        expected_res_var
            .enforce_equal_when_carried(&res_var)
            .unwrap();

        // 7. 모든 제약 조건이 만족하는지 확인
        println!(
            "RSA 스타일 17-bit pow_mod 제약 조건 수: {}",
            cs.num_constraints()
        );
        assert!(
            cs.is_satisfied().unwrap(),
            "RSA 스타일 17-bit pow_mod 제약 조건을 만족하지 못했습니다."
        );
    }
}
