use std::fs::File;

use bellman::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        multipack,
        sha256::sha256,
    },
    groth16::{self, Parameters},
    Circuit, ConstraintSystem, SynthesisError,
};
use bls12_381::{Bls12, Scalar};
use ff::PrimeField;
use pairing::Engine;
// use pairing::Engine;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zkp::{base64_decode_proof, base64_decode_verifying_key, base64_encode_proof};

fn flip_endianness(data: &[Boolean]) -> Vec<Boolean> {
    data.chunks(8)
        .map(|c| c.iter().rev())
        .flatten()
        .cloned()
        .collect()
}

struct MyCircuit {
    strength: Option<Scalar>,
    wisdom: Option<Scalar>,
    vitality: Option<Scalar>,
    agility: Option<Scalar>,
    concat_stat_bytes: Option<[u8; 32 * 4]>,
    total_stats: Option<Scalar>,
}

impl<Scalar: PrimeField> Circuit<Scalar> for MyCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // self.enforce_total_stats_constraint(cs)?;
        // let preimage = [self.strength, self.wisdom, self.vitality, self.agility]
        //     .iter()
        //     .fold(Some(vec![]), |acc, curr| {
        //         if let (Some(a), Some(c)) = (acc, curr) {
        //             Some([a, c.to_repr()].concat())
        //         } else {
        //             None
        //         }
        //     });

        // let preimage = preimage.map(|p| [p as u8; 80]);

        // Compute the values for the bits of the preimage. If we are verifying a proof,
        // we still need to create the same constraints, so we return an equivalent-size
        // Vec of None (indicating that the value of each bit is unknown).
        // let bit_values = if let Some(preimage) = preimage {
        //     preimage
        //         .into_iter()
        //         .map(|byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8))
        //         .flatten()
        //         .map(|b| Some(b))
        //         .collect()
        // } else {
        //     vec![None; 80 * 8]
        // };
        // assert_eq!(bit_values.len(), 80 * 8);

        // // Witness the bits of the preimage.
        // let preimage_bits = bit_values
        //     .into_iter()
        //     .enumerate()
        //     // Allocate each bit.
        //     .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("preimage bit {}", i)), b))
        //     // Convert the AllocatedBits into Booleans (required for the sha256 gadget).
        //     .map(|b| b.map(Boolean::from))
        //     .collect::<Result<Vec<_>, _>>()?;

        // talkja;ldkfj;slkdjf;lgkjsdl;fkjg
        // let concated: Option<Vec<u8>> = self.concat_stat_bytes.map(|b| b.to_vec());
        // let a: Option<Vec<u8>> = Some(vec![42; 32 * 4]);
        // dbg!(&concated == &a);

        let bit_values: Vec<Option<bool>> = if let Some(stat_bytes) = self.concat_stat_bytes {
            stat_bytes
                .into_iter()
                .map(|byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8))
                .flatten()
                .map(|b| Some(b))
                .collect()
        } else {
            vec![None; 32 * 4]
        };

        // dbg!(&bit_values);

        let preimage_bits = bit_values
            .into_iter()
            .enumerate()
            .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("preimage bit {}", i)), b))
            .map(|b| b.map(Boolean::from))
            .collect::<Result<Vec<_>, _>>()?;

        // dbg!(preimage_bits);
        // .map(|b| b.map(Boolean::from))

        // // // // Compute hash = SHA-256(preimage).
        let preimage_bits = flip_endianness(&preimage_bits);
        let hash = sha256(cs.namespace(|| "SHA-256(preimage)"), &preimage_bits)?;
        let hash = flip_endianness(&hash);

        // // // Expose the vector of 32 boolean variables as compact public inputs.
        multipack::pack_into_inputs(cs.namespace(|| "pack hash"), &hash)
    }
}

impl MyCircuit {
    fn enforce_total_stats_constraint<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // private inputs
        let strength = cs.alloc(
            || "strength",
            || self.strength.ok_or(SynthesisError::AssignmentMissing),
        )?;
        let wisdom = cs.alloc(
            || "wisdom",
            || self.wisdom.ok_or(SynthesisError::AssignmentMissing),
        )?;
        let agility = cs.alloc(
            || "agility",
            || self.agility.ok_or(SynthesisError::AssignmentMissing),
        )?;
        let vitality = cs.alloc(
            || "vitality",
            || self.vitality.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // public input
        let total_stats = cs.alloc_input(
            || "total stats",
            || self.total_stats.ok_or(SynthesisError::AssignmentMissing),
        )?;

        cs.enforce(
            || "sum stats = total allocation",
            |lc| lc + strength + wisdom + agility + vitality,
            |lc| lc + CS::one(),
            |lc| lc + total_stats,
        );
        Ok(())
    }

    fn concat_stat_bytes(&self) -> Option<Vec<u8>> {
        let s = self.strength.map(|s| s.to_bytes());
        let w = self.wisdom.map(|w| w.to_bytes());
        let v = self.vitality.map(|v| v.to_bytes());
        let a = self.agility.map(|a| a.to_bytes());

        [s, w, v, a].iter().fold(Some(vec![]), |acc, curr| {
            if let (Some(a), Some(c)) = (acc, curr) {
                Some([a, c.to_vec()].concat())
            } else {
                None
            }
        })
    }
}

fn main() {
    // Create parameters for our circuit. In a production deployment these would
    // be generated securely using a multiparty computation.
    let params = {
        let pfile = File::open("params.bin");
        if pfile.is_ok() {
            println!("read params");
            Parameters::read(pfile.unwrap(), false).unwrap()
        } else {
            let c = MyCircuit {
                strength: None,
                wisdom: None,
                vitality: None,
                agility: None,
                concat_stat_bytes: None,
                total_stats: None,
            };
            let p = groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap();
            let file = File::create("params.bin").unwrap();
            p.write(file).unwrap();
            p
        }
    };

    // Pick a preimage and compute its hash.
    // let preimage: [u8; 80] = [12; 80];

    // dbg!(preimage);

    // Create an instance of our circuit (with the preimage as a witness).
    let c = MyCircuit {
        strength: Scalar::from_str_vartime("10"),
        wisdom: Scalar::from_str_vartime("5"),
        vitality: Scalar::from_str_vartime("3"),
        agility: Scalar::from_str_vartime("2"),
        concat_stat_bytes: Some([42; 32 * 4]),
        total_stats: Scalar::from_str_vartime("20"),
    };

    // let cc = c.concat_stat_bytes().unwrap();
    // dbg!(&cc);
    let cc: Vec<u8> = vec![42; 32 * 4];
    let hash = Sha256::digest(cc);

    let proof = groth16::create_random_proof(c, &params, &mut OsRng);

    // let base64_proof = base64_encode_proof::<Bls12>(&proof.unwrap());
    // dbg!(base64_proof);

    // Pack the hash as inputs for proof verification.
    // let hash_bits = multipack::bytes_to_bits_le(&hash);

    // dbg!(&hash_bits);
    // let inputs = multipack::compute_multipacking::<Scalar>(&hash_bits);
    // dbg!(&inputs);
    // let inputs = [vec![Scalar::from_str_vartime("20").unwrap()], inputs].concat();

    // let pf: Scalar = PrimeField::from_str_vartime("20").unwrap();

    // let vk_s = "FiDvFl7qeUKvGgTj2MYpRCaAtrOdVm63nOC2HVnQFptmoylYOW5vR1UXea3uhzjHEfu4CKSQrxWHxSFJi7t0xtfnh9PTKtze1iKcxgFaYaOYEaibiabNAN7edc70AzeZA40Yj4noe9VbKfckHUB7GzDwZzTXUj8pTvgIOGQI6pv8igKiFWyD0h4w2dYB+lwNB1UeyNaemL3p5tm+CaJD8lpsNUcnYnf5qZEkSJNsS7uenhJcZnBNlDQ44PQfXQWDAX2x3sOmVcIS1tsQnAFDbk3qCwMtEUzJmQr02kdY8LW/E250P+0Itu2mPwBDipzJFXfTRGw7eH1K7bcPKtgvYil0Fo5Zzg5nLxyCNwUb5FG3/HxPlwyhFOsJxqoBcwD5Bfr7GI+9F/Pw96Dp6JCw7FMOMEE/iMYOHnbh+qwBGozhVhLRMPEj6GJlSJ06vZPRC+SaVnyN6TYaj6Y2rkhgol06/MIIrIWnvA3tq2kFGbznlj2s4cjW7VBog77pE+wEFZbCi0ixnlCIiRxMeC90UGirC+aKIwqJmeCDUvzNb1tIkT4xKt4IrcDweJ89r/rsEYD9kcTpLFcxl6lR7EPdcHwx9Wlbstp7o+ihToTLFEfFNMvP69gsivHXOyVg1jgSFwUGZYKDOIfaj33qxJeinuMZ8T7lN7Ri5P59b2kU+f0PgiElaB883mR39D+dcdXnD6lMYPx/kVcNpr/qYRC5Ocn7g0/1rh22qDW8ZYUaIcPXosbPcX59yPRE3bGvliJxCUbLbA4Wg53A3S6OBjNer4tQDW9ffDNi9R/A9/+BsdQHgH74a764hZOxnp2VOLG3F2CyHA7eNxLv6MZeMLlzrr70j5jp3m9ZtyjRzxNKR1O3Q7Jk846ZBl1M0dxGOHl4FIig9aFKFzYIdpwjb/8B3az1FCFrhve3ZvRBdoc0egfjcED6Z5drLHYv49P/WxTPA5D7/rBHibA1GkvaQ/r0JrC6boNYXmq4Wz/VMbPmBU9rwzwiRM5U6e98f53+TpMMAW8LNLwzl5qCoXlPfxWicJW5nWrReaMLrWOxp/32JOEnHcSs3+iyfwWx8cEqg3wHEjysVDXzuB2LNNd4chTYT151qKjZeTgBIdYVNTjT1g7/ekSu1DThomim2ypKjU/HAAAAAxfHLhpIu/5q3Ke9WetXP7AumEkqxGgQE+VrdgYTsDAPP/a18dNoYxOBqjVbS4uy4QG8nv7VoFnnc0kd0VoNu5tiV72pL9fpKm0GsqkRV1CdOZ3uQxwyZZ5lON5RbXaExw3vP7m+cO9Q29FdtFPTpVY4dORWxxyVvtE81U6+6zy7xdwpV789oEaRPEqi/BouvhjpB6gARcNX3bKN9HVlHvJmccN8O7UF+5UfSrlMJsil9uMHSVwRV+lEyeG0i01bFggPuRWd4ODSyYvGojrxo7lCPnfYPC1Vhy+uE3NI1nw8G8D6GKJkqBGJpGF/DhyengA1K3AibOf+BLwCAKzDNpQmUo+P3j0smnC2d+n8kp+t/WqaApj/6WIX+HuGR6gTIg==";
    // let vk = base64_decode_verifying_key::<Bls12>(vk_s).unwrap();

    // let proof_s = "rzkezTuERF++iGsJd2AOkxFFHbVecKpsuTENLs0pEjPD0XP5/ChRrBHWv27hBpEjkX/I9AqnzvdfoHPU+yXcaCeNKwPH/FQY1kaSLmy8WV8gaNFNbyTlwzhlggiyxj2REzGuR8+4Sl8YEw3p/uwE33WtDEVonCdWyr7iRyfS5ARh+30PO10gzun33K5jAy5tin2ORzgzxx53I8EDqz5JO4KSv9bGDNjOMeEl5tSJKAWauREbQeqGvRaejIIDI+vB";
    // let proof = base64_decode_proof::<Bls12>(proof_s).unwrap();

    // let pvk = groth16::prepare_verifying_key(&params.vk);

    // Check the proof!

    // assert!(groth16::verify_proof(&pvk, &proof.unwrap(), &inputs).is_ok());
}
