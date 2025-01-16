use clap::Parser;
use starknet_types_core::felt::Felt;

const PRIVATE_KEY: Felt =
    Felt::from_hex_unchecked("0x04cc2013dab13a1eb1512b2c605a3970fa0c177e31ae1a9d5bbea7129c12e51c");
const _PUBLIC_KEY: Felt =
    Felt::from_hex_unchecked("0x04e76282c35be857ab38dd07c06ca79fd9eb02280bbc457d207c25374b231711");

#[derive(Parser)]
struct Cli {
    #[arg(short, long)]
    nonce: String,
}

fn main() {
    let cli = Cli::parse();

    let signer = starknet_signers::SigningKey::from_secret_scalar(PRIVATE_KEY);

    let nonce_bytes = cdk::util::hex::decode(cli.nonce).unwrap();
    let low = u128::from_le_bytes(nonce_bytes[0..16].try_into().unwrap());
    let high = u128::from_le_bytes(nonce_bytes[16..32].try_into().unwrap());
    let nonce_hash = starknet_crypto::pedersen_hash(&low.into(), &high.into());

    let signature = signer.sign(&nonce_hash).unwrap();
    println!("r, s, nonce low, nonce high");
    println!("{} {} {} {}", signature.r, signature.s, low, high);
}
