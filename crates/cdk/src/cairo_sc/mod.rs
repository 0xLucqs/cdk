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
///
/// Given to the mint by the recipient
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CairoWitness {
    /// The serialize .json proof
    pub proof: String,
}

/// All the conditions the mint had to check before allowing the spending
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct CairoConditions {
    /// Expected output
    ///
    /// The mint should check that those values are the one written to the output segment of the proof
    pub output: Vec<Felt>,
}

// The other cashu spending conditions are built from this Vec<Vec<String>>.
// So here we are
impl From<CairoConditions> for Vec<Vec<String>> {
    fn from(value: CairoConditions) -> Self {
        let mut tags = Vec::new();

        if !value.output.is_empty() {
            let mut outputs = Vec::with_capacity(value.output.len());
            outputs.push("output".to_string());
            for o in value.output {
                outputs.push(o.to_string());
            }

            tags.push(outputs);
        }

        tags
    }
}

// Same, but the other way around
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

    // TODO: verify program hash
    // We should be able to compute an unique program hash from the proof
    let _ = Felt::from_str(&secret_data.data)?;

    // TODO: verify program output
    // We should be able to retrieve the nonce form the proof output segment
    let _nonce = {
        let mut hex_decode = hex::decode(&secret_data.nonce)?;
        hex_decode.resize(32, 0);
        let low = u128::from_le_bytes(hex_decode[0..16].try_into().unwrap());
        let high = u128::from_le_bytes(hex_decode[16..].try_into().unwrap());
        starknet_core::types::U256::from_words(low, high)
    };

    Ok(())
}

impl Proof {
    /// Verify a Cash Proof secured by a Cairo program
    pub fn verify_cairo(&self) -> Result<(), Error> {
        let secret: Nut10Secret = self.secret.clone().try_into()?;

        let cairo_witness = match &self.witness {
            None => return Err(anyhow!("WitnessExpectedForCairoSC")),
            Some(Witness::Cairo(witness)) => witness,
            _ => return Err(anyhow!("IncorrectSecretKind")),
        };

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
        const NONCE: &str = "babecafe";
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
