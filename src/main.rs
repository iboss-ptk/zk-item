use base64::DecodeError;
use bellman::groth16::{self, Parameters};
use bls12_381::Bls12;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::fs::File;
use zkp::{
    base64_decode_proof, base64_decode_verifying_key, base64_encode_proof, prepare_inputs,
    HiddenStatsCircuit,
};

fn main() {
    // Create parameters for our circuit. In a production deployment these would
    // be generated securely using a multiparty computation.
    let params = {
        let path = "params.bin";
        let pfile = File::open(path);

        // Read params from file
        if pfile.is_ok() {
            println!("read params");
            Parameters::read(pfile.unwrap(), false).unwrap()
        } else {
            let c = HiddenStatsCircuit {
                vit: None,
                wis: None,
                pow: None,
                agi: None,
            };
            // producing toxic wastes
            let p = groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap();
            p.write(File::create(path).unwrap()).unwrap();
            p
        }
    };

    let vit: u32 = 18;
    let wis: u32 = 11;
    let pow: u32 = 100;
    let agi: u32 = 1;

    let total_stats = vit + wis + pow + agi;

    let c = HiddenStatsCircuit {
        vit: Some(vit),
        wis: Some(wis),
        pow: Some(pow),
        agi: Some(agi),
    };

    // Hashing...
    // Deuplicate for demonstrating proof verification by changing params
    let preimage = (HiddenStatsCircuit {
        vit: Some(vit),
        wis: Some(wis),
        pow: Some(pow),
        agi: Some(agi),
    })
    .all_stats_bytes()
    .unwrap();
    let hash = Sha256::digest(&preimage);

    // Create a Groth16 proof with our parameters.
    let proof = groth16::create_random_proof(c, &params, &mut OsRng).unwrap();
    let hash_string = base64::encode(hash.to_vec());
    // dbg!(base64_encode_proof(&proof));

    let proof_string = base64_encode_proof(&proof).unwrap();

    // simulate_smart_contract(&proof_string, total_stats, &hash_string);

    let mut smart_contract = SimSmartContract::new("CQqssm3+bQI7OGC5MG3FfuP4kPhsyvFjjNl2SKHJn4OfaHHmq7sl2vQ/vwfvjh5OBHXh7j4diZB2Qbl0oIK8oepI2O1L+IrxbbqE9RBM9OrxLTa6H/m2j2bCXNxLZ85sEEdxVz+ZKm2y+EaoUYc43JIvKo2dzejzWPmxBiullb9ybrEl3s0ybqoKTM/FnVjjDALiBhlxMZEgp/C0I39pFDg8BYdhhm9Q7SFqr+pQdvaHWeBftUwu7m5Y7z3c24LvC8oVhF4oyHEzcGzEFQaX95dUVQWcILq33jjnkTMv1CWT99S/OKo3+NM8TGwCjNeYA0qPLGE8Ql+faK20WXIuyykugyXrrZZGDUMp3yRf3B1wWQNKcCE1JLBdbiNvNBDBGaGn6Ic8QErXWRZLifoEohZk3uTsiJGf1slBUXCmLOqrXSiq78p7SKXXYoV1lzBxD5YdiGIqe7lOurR23Er/3reuF4alOFg3T0ifbP4pWO1cdWDe1LlIjdFPGPUyO3ILBHycjQpDohAfbYioN+LFOtyQpRmEt6w0/SQie53bdsFMvfdGlO0R4qfrzMjtRjU5GGxbQ13XHSfA/f9qUv919vKqgPe46kTaDCUEEa7JJk+l6HJdzo53Ag7GcAQemfrfDNc3/K57qvVtm/GYsTwNY+B7tFLOoSFeySYUNXH8rIrjMAgSY9JLolDn8SS4cns7EQjUT41ASePIfYHrbaFUGO9e32nx2wj8pvg1S/z9VTVgP4CPECQlgV22nAUi2ZEOGTbijbxCUxZjG3DwaRzQBEaBHLgNyyBreq2AAuh9lvrGBNJhqYVpcqBDIf//oAkzC4fl4RQ7dlvr50JEm940DFqaOEm0CHUfEJ61N62Zq+gKpBLvfuUuL9OMLWNbZw79EJsMrbblArvCCJaOpQ/NsFSI8nGI3hTbkv8qBErOq5FkJTWKeghmkFboxCFvVDnhGPQ1mxxE+6hu0nZsNi9eYliL6qNL7MuCzDfwOqRDhzgTKDzDUnwDN1RLcZe2ko2XEJdJOl8Vsm8Mez/OLhydHjoP9D+wAK+JG656R6G29gXdHxh+YcIH+a9IhJ2sjDdGDivNvgiqvoxRk+6xiSUndY06Q5QarY+bMU6xGlz09IPsUqU13S8kdzMNPDLB8+T6AAAABAqC2O5Vs35583yPaOJcqD1Is1YuduxLOqYnU8losZRHS0n3KSGHiXB1I60CsH/h7gzg/egY1wjns3wyPASTNEnKlUSjbm9fwx+h11IlbIvOyKN1P188Tb1X4HD7ryKEtw6b3inqDqeAmQRoz8oEfBciTrXDsax/aKaSvpfFTJ/3hAQ/HV7Hm/0S/mAMf6+YKhBpRzskJLKYe0vG2hUpIw7jSt1zeutO5jY7W29mguvWNfYG0c7qthU69dk5MjUnZg6KnCB08GyV0U8pb0VCF8xDDktgQTnMFoJEJIvmrZsbjg7lODNd8w2s/NS06iEsegdKgOkuVqw+CqSoANDBVZIy8ifY5v58tR+SQjvu6bKhW5N4PV7fpFX+wFZwRtGl4hO03LrQSm5zZmEWILapp/d20ISoChMsTqRwKuQK47TrHn+iq421w4VpY0LUpVZqowe34RJheqYr+Dt3/s08qzIhDCS/cPKo7ilF7KItaHwUEqNwN9YyEABpRUK8Ka1sNw==");

    // create new charactor with hidden stats
    smart_contract
        .new_character(&proof_string, total_stats, &hash_string)
        .unwrap();

    dbg!(&smart_contract.character);

    println!("\n\n============================\n\n");

    smart_contract.reveal_stats(&vit, &wis, &pow, &agi);

    dbg!(&smart_contract.character);
}

// Smart Contract Simulation

#[derive(Debug)]
enum Character<'a> {
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
struct SimSmartContract<'a> {
    vk_string: &'a str,
    character: Option<Character<'a>>,
}

impl<'a> SimSmartContract<'a> {
    fn new(vk_string: &'a str) -> Self {
        Self {
            vk_string,
            character: None,
        }
    }
    fn new_character(
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
            println!("create new character with:");
            println!("  total stats: {total_stats}");
            println!("  hash: {hash_string}");
            self.character = Some(Character::Hidden {
                total_stats,
                hash_string,
                proof_string,
            })
        } else {
            println!("verification error!");
        }
        Ok(())
    }

    fn reveal_stats(&mut self, vit: &'a u32, wis: &'a u32, pow: &'a u32, agi: &'a u32) {
        if let Some(character) = &self.character {
            let stats_bytes = [vit, wis, pow, agi].map(|s| s.to_le_bytes()).concat();
            let hash = Sha256::digest(&stats_bytes);
            let hash = base64::encode(hash);

            match character {
                Character::Hidden {
                    total_stats: _,
                    hash_string,
                    proof_string: _,
                } => {
                    // IMPORTANT!!
                    if &hash == *hash_string {
                        self.character = Some(Character::Revealed { vit, wis, pow, agi });
                        println!("revealing...");
                    } else {
                        println!("invalid hash, not allowed to reveal!")
                    }
                }
                Character::Revealed {
                    vit: _,
                    wis: _,
                    pow: _,
                    agi: _,
                } => {
                    println!("already revealed!")
                }
            }
        } else {
            println!("character does not exists!")
        }
    }
}
