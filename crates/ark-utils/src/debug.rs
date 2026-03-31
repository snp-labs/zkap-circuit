//! Debug macros for constraint logging in ark-utils.
//!
//! These macros are gated by the `constraints-logging` feature flag.
//! In production builds (without the feature), they compile to just the enforce call.

/// Internal enforce for Boolean == TRUE with debug logging.
/// Logs file and line number on mismatch.
#[macro_export]
macro_rules! enforce_true_internal {
    ($label:expr, $result:expr) => {{
        #[cfg(feature = "constraints-logging")]
        {
            use ark_r1cs_std::R1CSVar;
            if let Ok(v) = $result.value() {
                if !v {
                    println!(
                        "[r1cs:internal] {}: FAILED (expected true, got false) at {}:{}",
                        $label,
                        file!(),
                        line!()
                    );
                }
            }
        }
        $result.enforce_equal(&ark_r1cs_std::prelude::Boolean::TRUE)
    }};
}

/// Internal enforce for value equality with debug logging.
/// Logs file and line number on mismatch.
#[macro_export]
macro_rules! enforce_eq_internal {
    ($label:expr, $lhs:expr, $rhs:expr) => {{
        #[cfg(feature = "constraints-logging")]
        {
            use ark_r1cs_std::R1CSVar;
            match ($lhs.value(), $rhs.value()) {
                (Ok(l), Ok(r)) if l != r => {
                    println!(
                        "[r1cs:internal] {}: MISMATCH at {}:{}",
                        $label,
                        file!(),
                        line!()
                    );
                    println!("  lhs={:?}", l);
                    println!("  rhs={:?}", r);
                }
                _ => {}
            }
        }
        $lhs.enforce_equal(&$rhs)
    }};
}
