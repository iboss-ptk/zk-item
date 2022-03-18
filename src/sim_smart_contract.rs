// Smart Contract Simulation

use base64::DecodeError;
use bellman::groth16;
use bls12_381::Bls12;
use sha2::{Digest, Sha256};

use crate::utils::{base64_decode_proof, base64_decode_verifying_key, prepare_inputs};

#[derive(Debug)]
pub enum Item<'a> {
    Hidden {
        total_stats: u32,
        hash_string: &'a str,
        proof_string: &'a str,
    },
    Revealed {
        vit: &'a u32,
        wis: &'a u32,
        pow: &'a u32,
        agi: &'a u32,
    },
}

#[derive(Debug)]
pub struct SimSmartContract<'a> {
    pub vk_string: &'a str,
    pub item: Option<Item<'a>>,
}

impl<'a> SimSmartContract<'a> {
    pub fn new(vk_string: &'a str) -> Self {
        Self {
            vk_string,
            item: None,
        }
    }
    pub fn new_item(
        &mut self,
        proof_string: &'a str,
        total_stats: u32,
        hash_string: &'a str,
    ) -> Result<(), DecodeError> {
        // smart contract states

        let vk = base64_decode_verifying_key::<Bls12>(self.vk_string)?;
        let pvk = groth16::prepare_verifying_key(&vk);

        let proof = base64_decode_proof::<Bls12>(&proof_string)?;
        let hash = base64::decode(&hash_string)?;
        let inputs = prepare_inputs(total_stats, &hash);

        // IMPORTANT!!
        let verification = groth16::verify_proof(&pvk, &proof, &inputs);

        if verification.is_ok() {
            println!("create new item with:");
            println!("  total stats: {total_stats}");
            println!("  hash: {hash_string}");
            self.item = Some(Item::Hidden {
                total_stats,
                hash_string,
                proof_string,
            })
        } else {
            println!("verification error!");
        }
        Ok(())
    }

    pub fn reveal_stats(&mut self, vit: &'a u32, wis: &'a u32, pow: &'a u32, agi: &'a u32) {
        if let Some(item) = &self.item {
            let stats_bytes = [vit, wis, pow, agi].map(|s| s.to_le_bytes()).concat();
            let hash = Sha256::digest(&stats_bytes);
            let hash = base64::encode(hash);

            match item {
                Item::Hidden {
                    total_stats: _,
                    hash_string,
                    proof_string: _,
                } => {
                    // IMPORTANT!!
                    if &hash == *hash_string {
                        self.item = Some(Item::Revealed { vit, wis, pow, agi });
                        println!("revealing...");
                    } else {
                        println!("invalid hash, not allowed to reveal!")
                    }
                }
                Item::Revealed {
                    vit: _,
                    wis: _,
                    pow: _,
                    agi: _,
                } => {
                    println!("already revealed!")
                }
            }
        } else {
            println!("item does not exists!")
        }
    }
}
