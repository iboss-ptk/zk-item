use bellman::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        multipack,
        sha256::sha256,
    },
    Circuit, ConstraintSystem, SynthesisError,
};
use ff::PrimeField;

use crate::utils::flip_endianness;

pub struct HiddenStatsCircuit {
    pub vit: Option<u32>,
    pub wis: Option<u32>,
    pub pow: Option<u32>,
    pub agi: Option<u32>,
}

impl<Scalar: PrimeField> Circuit<Scalar> for HiddenStatsCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        self.enforce_total_stats_constraint(cs)?;

        // Compute hash = SHA-256d(preimage).
        let preimage_bits = flip_endianness(&self.preimage_bits(cs)?);
        let hash = sha256(cs.namespace(|| "SHA-256d(preimage)"), &preimage_bits)?;
        let hash = flip_endianness(&hash);
        multipack::pack_into_inputs(cs.namespace(|| "pack hash"), &hash)
    }
}

impl HiddenStatsCircuit {
    pub fn all_stats_bytes(&self) -> Option<Vec<u8>> {
        let stats = [self.vit, self.wis, self.pow, self.agi]
            .into_iter()
            .collect::<Option<Vec<u32>>>();

        stats.map(|s| s.into_iter().flat_map(|s| s.to_le_bytes()).collect())
    }

    fn preimage_bits<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<Boolean>, SynthesisError> {
        let bit_values = if let Some(stats) = self.all_stats_bytes() {
            stats
                .into_iter()
                .map(|byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8))
                .flatten()
                .map(|b| Some(b))
                .collect()
        } else {
            vec![None; 4 * 32]
        };

        assert_eq!(bit_values.len(), 4 * 32);

        // Witness the bits of the preimage.
        bit_values
            .into_iter()
            .enumerate()
            .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("preimage bit {}", i)), b))
            .map(|b| b.map(Boolean::from))
            .collect::<Result<Vec<_>, _>>()
    }

    fn enforce_total_stats_constraint<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        fn to_scalar<Scalar: PrimeField>(s: &Option<u32>) -> Result<Scalar, SynthesisError> {
            s.map(|s| Scalar::from(s as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        }
        // private inputs
        let vit = cs.alloc(|| "vit", || to_scalar(&self.vit))?;
        let wis = cs.alloc(|| "wis", || to_scalar(&self.wis))?;
        let pow = cs.alloc(|| "pow", || to_scalar(&self.pow))?;
        let agi = cs.alloc(|| "agi", || to_scalar(&self.agi))?;

        // sum all stats
        let total_stats_val = [self.vit, self.wis, self.pow, self.agi]
            .into_iter()
            .collect::<Option<Vec<u32>>>()
            .map(|stats| stats.into_iter().reduce(|acc, curr| acc + curr))
            .flatten();

        // public input
        let total_stats = cs.alloc_input(|| "total stats", || to_scalar(&total_stats_val))?;

        cs.enforce(
            || "sum stats = total allocation",
            |lc| lc + vit + wis + pow + agi,
            |lc| lc + CS::one(),
            |lc| lc + total_stats,
        );
        Ok(())
    }
}
