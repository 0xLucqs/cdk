pub mod serde_cairo_witness;

use std::str::FromStr;

use anyhow::{anyhow, Error, Result};
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;
use stwo_cairo_prover::cairo_air::air::CairoProof;
use stwo_cairo_prover::cairo_air::verify_cairo;
use stwo_prover::core::vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};

use crate::nuts::{Nut10Secret, Proof, SecretData, Witness};
use crate::util::hex;

/// The Witness of a cairo program
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CairoWitness {
    pub proof: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct CairoConditions {
    pub output: Vec<Felt>,
}

impl From<CairoConditions> for Vec<Vec<String>> {
    fn from(value: CairoConditions) -> Self {
        let mut tags = Vec::new();

        let mut outputs = Vec::with_capacity(value.output.len());
        outputs.push("output".to_string());
        for o in value.output {
            outputs.push(o.to_string());
        }

        tags.push(outputs);

        tags
    }
}

impl TryFrom<Vec<Vec<String>>> for CairoConditions {
    type Error = String;

    fn try_from(value: Vec<Vec<String>>) -> std::result::Result<Self, Self::Error> {
        let mut ret = Self::default();

        for tag in value {
            match tag[0].as_str() {
                "output" => {
                    ret.output = tag[1..]
                        .iter()
                        .map(|s| Felt::from_str(s))
                        .collect::<Result<_, _>>()
                        .map_err(|e| e.to_string())?;
                }
                _ => {}
            }
        }

        Ok(ret)
    }
}

fn verify(secret_data: SecretData, witness: &CairoWitness) -> Result<()> {
    let cairo_proof: CairoProof<Blake2sMerkleHasher> =
        serde_json::from_str(&witness.proof).unwrap();
    verify_cairo::<Blake2sMerkleChannel>(cairo_proof).unwrap();
    println!("proof VERIFIED");

    // TODO: check program hash
    println!("program hash: {}", &secret_data.data);
    let _ = Felt::from_str(&secret_data.data)?;
    // TODO: check program output
    println!("nonce: {}", &secret_data.nonce);
    let hex_decode = hex::decode(&secret_data.nonce)?;
    let low = u128::from_le_bytes(hex_decode[0..16].try_into().unwrap());
    let high = u128::from_le_bytes(hex_decode[16..32].try_into().unwrap());
    let nonce = starknet_core::types::U256::from_words(low, high);
    println!("nonce: {:#x}", nonce);

    Ok(())
}

impl Proof {
    /// Verify a Cash Proof secured by a Cairo program
    pub fn verify_cairo(&self) -> Result<(), Error> {
        println!("verify cairo");
        let secret: Nut10Secret = self.secret.clone().try_into()?;
        println!("secret ok");

        let cairo_witness = match &self.witness {
            None => return Err(anyhow!("WitnessExpectedForCairoSC")),
            Some(Witness::Cairo(witness)) => witness,
            _ => return Err(anyhow!("IncorrectSecretKind")),
        };
        println!("withness ok");

        verify(secret.secret_data, cairo_witness)
    }
}

#[cfg(test)]
mod cairo {
    use std::path::PathBuf;

    use crate::cairo_sc::{verify, CairoWitness};
    use crate::nuts::SecretData;

    #[test]
    fn it_works() -> Result<(), anyhow::Error> {
        const NONCE: &str = "0xbabecafe";
        const PATH_TO_CAIRO_PROOF: &str =
            "/Users/tdelabro/Documents/code/starkware/cdk/spending_conditions/stwo-proof.json";

        let proof = {
            let path = PathBuf::from(PATH_TO_CAIRO_PROOF);
            std::fs::read_to_string(path).unwrap()
        };
        let cairo_witness = CairoWitness { proof };

        let secret_data = SecretData {
            nonce: NONCE.to_string(),
            data: "-1608947684670054274702912680566326313189518019374810093783102571404495623498"
                .to_string(),
            tags: None,
        };

        verify(secret_data, &cairo_witness)?;

        Ok(())
    }
}
