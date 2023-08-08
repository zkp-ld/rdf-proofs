use crate::{constants::GENERATOR_SEED, error::KeyGenError, Fr};
use ark_bls12_381::Bls12_381;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::rngs::StdRng;
use bbs_plus::{
    prelude::{KeypairG2 as BBSKeyPairG2, SignatureParamsG1 as BBSSignatureParamsG1},
    setup::{PublicKeyG2, SecretKey},
};
use blake2::Blake2b512;
use multibase::Base;

pub fn params_gen(message_count: usize) -> BBSSignatureParamsG1<Bls12_381> {
    // TODO: to be fixed
    BBSSignatureParamsG1::<Bls12_381>::new::<Blake2b512>(GENERATOR_SEED, message_count)
}

pub fn key_gen(rng: &mut StdRng) -> Result<(String, String), KeyGenError> {
    let base_params = params_gen(1); // TODO: to be justified

    let keypair = BBSKeyPairG2::<Bls12_381>::generate_using_rng(rng, &base_params);

    let mut secret_key_bytes = Vec::new();
    keypair
        .secret_key
        .serialize_compressed(&mut secret_key_bytes)?;
    let secret_key_base64url = multibase::encode(Base::Base64Url, secret_key_bytes);

    let mut public_key_bytes = Vec::new();
    keypair
        .public_key
        .serialize_compressed(&mut public_key_bytes)?;
    let public_key_base64url = multibase::encode(Base::Base64Url, public_key_bytes);

    Ok((secret_key_base64url, public_key_base64url))
}

pub fn deserialize_secret_key(key: &str) -> Result<SecretKey<Fr>, KeyGenError> {
    let (_, key_bytes) = multibase::decode(key)?;
    Ok(SecretKey::<Fr>::deserialize_compressed(&*key_bytes)?)
}

pub fn deserialize_public_key(key: &str) -> Result<PublicKeyG2<Bls12_381>, KeyGenError> {
    let (_, key_bytes) = multibase::decode(key)?;
    Ok(PublicKeyG2::<Bls12_381>::deserialize_compressed(
        &*key_bytes,
    )?)
}

#[cfg(test)]
mod tests {
    use super::key_gen;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn key_gen_simple() -> () {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed
        let (secret_key, public_key) = key_gen(&mut rng).unwrap();
        println!("secret_key: {}", secret_key);
        println!("public_key: {}", public_key);

        assert!(true);
    }
}
