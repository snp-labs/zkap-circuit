use ark_r1cs_std::R1CSVar;

#[cfg(feature = "constraints-logging")]
pub fn log_r1cs_eq<F, V>(label: &str, var1: &[V], var2: &[V])
where
    F: ark_ff::Field,
    V: ark_r1cs_std::R1CSVar<F>,
    V::Value: core::fmt::Debug,
{
    match (var1.value(), var2.value()) {
        (Ok(v1), Ok(v2)) => println!("{}: {:?}", label, v1 == v2),
        (e1, e2) => println!("{}: value unavailable ({:?}, {:?})", label, e1.err(), e2.err()),
    }
}