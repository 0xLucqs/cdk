use core::ecdsa::check_ecdsa_signature;
use core::pedersen::pedersen;

#[derive(Drop, Debug, Serde)]
pub struct Inputs {
    nonce: u256,
    signature: Sig,
}

#[derive(Drop, Debug, Serde)]
pub struct Sig {
    r: felt252,
    s: felt252,
}

// Only the private key linked to this public key can sign it
const EXPECTED_SIGNER_PUBKEY: felt252 = 0x04e76282c35be857ab38dd07c06ca79fd9eb02280bbc457d207c25374b231711;

fn main(
    raw_inputs: Array<felt252>,
) -> Array<felt252> {
    let inputs: Inputs  = {
    let mut inputs_ref = raw_inputs.span();
     Serde::deserialize(ref inputs_ref).expect('bad program arguments')
    };

    if !verify_signature(inputs.nonce, inputs.signature.r, inputs.signature.s) {
        panic!("bad signature");
    };

    let nonce_low = inputs.nonce.low;
    let nonce_high = inputs.nonce.high;

    return array![nonce_low.into(), nonce_high.into()];
}

fn verify_signature(nonce: u256, r: felt252, s: felt252) -> bool {
    let nonce_hash = pedersen(nonce.low.into(), nonce.high.into());
    check_ecdsa_signature(nonce_hash, EXPECTED_SIGNER_PUBKEY, r, s)
}

