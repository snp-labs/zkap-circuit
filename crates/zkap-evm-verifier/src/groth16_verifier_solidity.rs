//! Groth16 Solidity verifier contract generator.
//!
//! [`SolidityContractGenerator`] is implemented for [`ark_groth16::VerifyingKey<E>`]
//! and writes a self-contained `Groth16Verifier.sol` that embeds the verifying-key
//! constants. Called by `zkap_service::crs::persist_setup_output` during trusted setup.

use ark_ec::{AffineRepr, pairing::Pairing};
use ark_ff::Field;
use ark_groth16::data_structures::VerifyingKey;
use ark_std::{ops::Neg, path::Path};

pub trait SolidityContractGenerator {
    fn generate_solidity<P: AsRef<Path>>(&self, path: P) -> Result<(), std::io::Error>;
}

fn g1_constant<E: Pairing>(g1: &E::G1Affine, tag: &str) -> String {
    let x = g1.x().unwrap_or_default();
    let y = g1.y().unwrap_or_default();
    [
        format!("\tuint256 private constant {}X = {};", tag, x),
        format!("\tuint256 private constant {}Y = {};", tag, y),
    ]
    .join("\n")
}

fn g2_constant<E: Pairing>(g2: E::G2Affine, tag: &str) -> String {
    let x = g2
        .x()
        .unwrap_or_default()
        .to_base_prime_field_elements()
        .collect::<Vec<_>>();
    let y = g2
        .y()
        .unwrap_or_default()
        .to_base_prime_field_elements()
        .collect::<Vec<_>>();
    [
        format!("\tuint256 private constant {}X0 = {};", tag, x[1]),
        format!("\tuint256 private constant {}X1 = {};", tag, x[0]),
        format!("\tuint256 private constant {}Y0 = {};", tag, y[1]),
        format!("\tuint256 private constant {}Y1 = {};", tag, y[0]),
    ]
    .join("\n")
}

impl<E: Pairing> SolidityContractGenerator for VerifyingKey<E> {
    fn generate_solidity<P: AsRef<Path>>(&self, path: P) -> Result<(), std::io::Error> {
        let header = [
            "// SPDX-License-Identifier: GPL-3.0".to_string(),
            "pragma solidity ^0.8.0;".to_string(),
            String::new(),
            "library Groth16Verifier {".to_string(),
            "\terror InvalidProofLength();".to_string(),
            "\terror InvalidInstanceLength();".to_string(),
            "\terror PrepareInstanceFailed();".to_string(),
            "\terror PairingFailed();".to_string(),
            String::new(),
        ];

        let mut constants = vec![
            String::from("\t// solhint-disable const-name-snakecase"),
            g1_constant::<E>(&self.alpha_g1, "alpha"),
            g2_constant::<E>(self.beta_g2.into_group().neg().into(), "beta"),
            g2_constant::<E>(self.gamma_g2.into_group().neg().into(), "gamma"),
            g2_constant::<E>(self.delta_g2.into_group().neg().into(), "delta"),
            String::new(),
        ];

        for (i, gamma_abc) in self.gamma_abc_g1.iter().enumerate() {
            constants.extend([
                g1_constant::<E>(gamma_abc, &format!("ic{:03}", i)),
                String::new(),
            ]);
        }

        let function_define = [
            String::from("\t// solhint-disable-next-line function-max-lines"),
            format!(
                "\tfunction _verify(uint256[{}] calldata instance, uint256[8] calldata proof) public view returns (bool) {{",
                self.gamma_abc_g1.len() - 1
            ),
            String::from("\t\tif (proof.length != 8) revert InvalidProofLength();"),
            format!(
                "\t\tif (instance.length != {}) revert InvalidInstanceLength();",
                self.gamma_abc_g1.len() - 1
            ),
            String::new(),
            String::from("\t\tuint256[24] memory io;"),
            String::from("\t\tbool success = true;"),
            String::new(),
        ];

        let mut prepare_instance = vec![
            String::from("\t\tassembly {"),
            String::from("\t\t\tlet g := sub(gas(), 2000)"),
            String::new(),
            String::from("\t\t\tmstore(add(io, 0x240), ic000X)"),
            String::from("\t\t\tmstore(add(io, 0x260), ic000Y)"),
            String::new(),
        ];

        for i in 1..self.gamma_abc_g1.len() {
            prepare_instance.extend([
                format!("\t\t\tmstore(add(io, 0x280), ic{:03}X)", i),
                format!("\t\t\tmstore(add(io, 0x2a0), ic{:03}Y)", i),
                format!("\t\t\tmstore(add(io, 0x2c0), calldataload(add(instance, 0x{:03x})))", (i - 1) << 5),
                String::from(
                    "\t\t\tsuccess := and(success, staticcall(g, 0x07, add(io, 0x280), 0x60, add(io, 0x280), 0x40))",
                ),
                String::from(
                    "\t\t\tsuccess := and(success, staticcall(g, 0x06, add(io, 0x240), 0x80, add(io, 0x240), 0x40))",
                ),
                String::new(),
            ]);
        }

        prepare_instance.extend([
            String::from("\t\t}"),
            String::from("\t\tif (!success) revert PrepareInstanceFailed();"),
            String::new(),
        ]);

        let groth_verify = [
            String::from("\t\tassembly {"),
            String::from("\t\t\t// input 0x000 ~ 0x040 : A"),
            String::from("\t\t\t// input 0x040 ~ 0x0c0 : B"),
            String::from("\t\t\tmstore(io, calldataload(proof)) // A.X"),
            String::from("\t\t\tmstore(add(io, 0x020), calldataload(add(proof, 0x20))) // A.Y"),
            String::from("\t\t\tmstore(add(io, 0x040), calldataload(add(proof, 0x40))) // B.X0"),
            String::from("\t\t\tmstore(add(io, 0x060), calldataload(add(proof, 0x60))) // B.X1"),
            String::from("\t\t\tmstore(add(io, 0x080), calldataload(add(proof, 0x80))) // B.Y0"),
            String::from("\t\t\tmstore(add(io, 0x0a0), calldataload(add(proof, 0xa0))) // B.Y1"),
            String::new(),
            String::from("\t\t\t// input 0x0c0 ~ 0x100 : alpha"),
            String::from("\t\t\t// input 0x100 ~ 0x180 : -beta"),
            String::from("\t\t\tmstore(add(io, 0x0c0), alphaX)"),
            String::from("\t\t\tmstore(add(io, 0x0e0), alphaY)"),
            String::from("\t\t\tmstore(add(io, 0x100), betaX0)"),
            String::from("\t\t\tmstore(add(io, 0x120), betaX1)"),
            String::from("\t\t\tmstore(add(io, 0x140), betaY0)"),
            String::from("\t\t\tmstore(add(io, 0x160), betaY1)"),
            String::new(),
            String::from("\t\t\t// input 0x180 ~ 0x1c0 : C"),
            String::from("\t\t\t// input 0x1c0 ~ 0x240 : -delta"),
            String::from("\t\t\tmstore(add(io, 0x180), calldataload(add(proof, 0xc0))) // C.X"),
            String::from("\t\t\tmstore(add(io, 0x1a0), calldataload(add(proof, 0xe0))) // C.Y"),
            String::from("\t\t\tmstore(add(io, 0x1c0), deltaX0)"),
            String::from("\t\t\tmstore(add(io, 0x1e0), deltaX1)"),
            String::from("\t\t\tmstore(add(io, 0x200), deltaY0)"),
            String::from("\t\t\tmstore(add(io, 0x220), deltaY1)"),
            String::new(),
            String::from("\t\t\t// input 0x280 ~ 0x300 : -gamma"),
            String::from("\t\t\tmstore(add(io, 0x280), gammaX0)"),
            String::from("\t\t\tmstore(add(io, 0x2a0), gammaX1)"),
            String::from("\t\t\tmstore(add(io, 0x2c0), gammaY0)"),
            String::from("\t\t\tmstore(add(io, 0x2e0), gammaY1)"),
            String::new(),
            String::from(
                "\t\t\tsuccess := staticcall(sub(gas(), 2000), 0x08, io, 0x300, io, 0x020)",
            ),
            String::from("\t\t}"),
            String::from("\t\tif (!success) revert PairingFailed();"),
        ];

        let footer = [
            String::from("\t\treturn io[0] == 1;"),
            String::from("\t}"),
            String::from("}"),
        ];

        let solidity = [
            &header,
            &constants[..],
            &function_define,
            &prepare_instance[..],
            &groth_verify,
            &footer,
        ]
        .concat()
        .join("\n");

        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, solidity.as_bytes())?;
        Ok(())
    }
}
