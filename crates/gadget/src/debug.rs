
use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::R1CSVar;

#[inline]
pub fn log_delta<F: Field>(
    _cs: &ConstraintSystemRef<F>,
    _label: &str,
    _last: &mut usize,
) -> Result<(), SynthesisError> {
    #[cfg(feature = "num-cs-logging")]
    {
        let now = _cs.num_constraints();
        let delta = now.saturating_sub(*_last);
        println!("[r1cs] {:<32} +{}", _label, delta);
        *_last = now;
    }
    Ok(())
}

// 총 제약수 출력
#[inline]
pub fn log_total<F: Field>(
    _cs: &ConstraintSystemRef<F>,
    _label: &str,
) -> Result<(), SynthesisError> {
    #[cfg(feature = "num-cs-logging")]
    {
        let now = _cs.num_constraints();
        println!("[r1cs] {:<32} total={}", _label, now);
    }
    Ok(())
}


#[inline]
pub fn log_r1cs_eq<F, V>(_label: &str, _lhs: &[V], _rhs: &[V])
where
    F: Field,
    V: R1CSVar<F>,
    V::Value: core::fmt::Debug + PartialEq,
{
    #[cfg(feature = "constraints-logging")]
    {
        if _lhs.len() != _rhs.len() {
            println!(
                "[r1cs] {}: len mismatch (lhs={}, rhs={})",
                _label,
                _lhs.len(),
                _rhs.len()
            );
        }

        let v1 = _lhs.value();
        let v2 = _rhs.value();

        match (v1, v2) {
            (Ok(v1), Ok(v2)) => {
                let min_len = core::cmp::min(v1.len(), v2.len());
                let mut first_diff: Option<usize> = None;

                for i in 0..min_len {
                    if v1[i] != v2[i] {
                        first_diff = Some(i);
                        break;
                    }
                }

                let eq = first_diff.is_none() && v1.len() == v2.len();

                match first_diff {
                    None => {
                        if eq {
                            println!("[r1cs] {}: equal (len={})", _label, v1.len());
                        } else {
                            println!(
                                "[r1cs] {}: not equal (length differs: lhs={}, rhs={})",
                                _label,
                                v1.len(),
                                v2.len()
                            );
                        }
                    }
                    Some(i) => {
                        println!(
                            "[r1cs] {}: not equal (first mismatch @ idx {}): lhs={:?}, rhs={:?}",
                            _label, i, v1[i], v2[i]
                        );
                    }
                }
            }
            (Err(e1), Err(e2)) => {
                println!(
                    "[r1cs] {}: value unavailable (lhs={:?}, rhs={:?})",
                    _label, e1, e2
                );
            }
            (Err(e1), Ok(_)) => println!("[r1cs] {}: value unavailable (lhs={:?}, rhs=ok)", _label, e1),
            (Ok(_), Err(e2)) => println!("[r1cs] {}: value unavailable (lhs=ok, rhs={:?})", _label, e2),
        }
    }
}

#[macro_export]
macro_rules! dbg_r1cs_eq {
    ($label:expr, $lhs:expr, $rhs:expr) => {{
        #[cfg(feature = "constraints-logging")]
        {
            use core::slice;
            $crate::debug::log_r1cs_eq($label, slice::from_ref(&$lhs), slice::from_ref(&$rhs));
        }
    }};
}

#[macro_export]
macro_rules! dbg_r1cs_eq_slice {
    ($label:expr, $lhs:expr, $rhs:expr) => {{
        #[cfg(feature = "constraints-logging")]
        {
            $crate::debug::log_r1cs_eq($label, &$lhs, &$rhs);
        }
    }};
}

#[macro_export]
macro_rules! dbg_cs_delta {
    ($cs:expr, $last:expr, $label:expr) => {{
        #[cfg(feature = "num-cs-logging")]
        {
            let _ = $crate::debug::log_delta($cs, $label, $last);
        }
    }};
}


#[macro_export]
macro_rules! dbg_cs_total {
    ($cs:expr, $label:expr) => {{
        #[cfg(feature = "num-cs-logging")]
        {
            let _ = $crate::debug::log_total($cs, $label);
        }
    }};
}