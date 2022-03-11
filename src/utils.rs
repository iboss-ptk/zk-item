use std::io::{self, Cursor};

use base64::DecodeError;
use bellman::{
    gadgets::{boolean::Boolean, multipack},
    groth16::{Proof, VerifyingKey},
};
use bls12_381::Scalar;
use pairing::Engine;

pub fn base64_encode_verifying_key<E: Engine>(vk: &VerifyingKey<E>) -> io::Result<String> {
    let mut v = Vec::new();
    vk.write(&mut v)?;
    Ok(base64::encode(v))
}

pub fn base64_decode_verifying_key<E: Engine>(
    vk_string: &str,
) -> Result<VerifyingKey<E>, DecodeError> {
    let vk = base64::decode(vk_string)?;
    Ok(VerifyingKey::<E>::read(Cursor::new(vk)).unwrap())
}

pub fn base64_encode_proof<E: Engine>(proof: &Proof<E>) -> io::Result<String> {
    let mut v = Vec::new();
    proof.write(&mut v)?;
    Ok(base64::encode(v))
}

pub fn base64_decode_proof<E: Engine>(proof_string: &str) -> Result<Proof<E>, DecodeError> {
    let proof = base64::decode(proof_string)?;
    Ok(Proof::<E>::read(Cursor::new(proof)).unwrap())
}

pub fn prepare_inputs(total_stats: u32, hash: &Vec<u8>) -> Vec<Scalar> {
    let total_stats_scalar = Scalar::from_raw([total_stats as u64, 0, 0, 0]);
    // Pack the hash as inputs for proof verification.
    let hash_bits = multipack::bytes_to_bits_le(&hash);
    [
        vec![total_stats_scalar],
        multipack::compute_multipacking(&hash_bits),
    ]
    .concat()
}

pub fn flip_endianness(data: &[Boolean]) -> Vec<Boolean> {
    data.chunks(8)
        .map(|c| c.iter().rev())
        .flatten()
        .cloned()
        .collect()
}
