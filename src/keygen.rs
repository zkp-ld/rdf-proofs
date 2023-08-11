use crate::{common::Fr, constants::GENERATOR_SEED, error::RDFProofsError};
use ark_bls12_381::Bls12_381;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
use bbs_plus::{
    prelude::{KeypairG2 as BBSKeypairG2, SignatureParamsG1 as BBSSignatureParamsG1},
    setup::{PublicKeyG2 as BBSPublicKeyG2, SecretKey as BBSSecretKey},
};
use blake2::Blake2b512;
use multibase::Base;

pub fn generate_params(message_count: usize) -> BBSSignatureParamsG1<Bls12_381> {
    // TODO: to be fixed
    BBSSignatureParamsG1::<Bls12_381>::new::<Blake2b512>(GENERATOR_SEED, message_count)
}

pub fn generate_keypair<R: RngCore>(
    rng: &mut R,
) -> Result<BBSKeypairG2<Bls12_381>, RDFProofsError> {
    let base_params = generate_params(1); // TODO: to be justified

    Ok(BBSKeypairG2::<Bls12_381>::generate_using_rng(
        rng,
        &base_params,
    ))
}

pub fn serialize_secret_key(key: &BBSSecretKey<Fr>) -> Result<String, RDFProofsError> {
    let mut key_bytes = Vec::new();
    key.serialize_compressed(&mut key_bytes)?;
    Ok(multibase::encode(Base::Base64Url, key_bytes))
}

pub fn serialize_public_key(key: &BBSPublicKeyG2<Bls12_381>) -> Result<String, RDFProofsError> {
    let mut key_bytes = Vec::new();
    key.serialize_compressed(&mut key_bytes)?;
    Ok(multibase::encode(Base::Base64Url, key_bytes))
}

pub fn deserialize_secret_key(key: &str) -> Result<BBSSecretKey<Fr>, RDFProofsError> {
    let (_, key_bytes) = multibase::decode(key)?;
    Ok(BBSSecretKey::<Fr>::deserialize_compressed(&*key_bytes)?)
}

pub fn deserialize_public_key(key: &str) -> Result<BBSPublicKeyG2<Bls12_381>, RDFProofsError> {
    let (_, key_bytes) = multibase::decode(key)?;
    Ok(BBSPublicKeyG2::<Bls12_381>::deserialize_compressed(
        &*key_bytes,
    )?)
}

#[cfg(test)]
mod tests {
    use super::generate_keypair;
    use crate::keygen::{serialize_public_key, serialize_secret_key};
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn key_gen_simple() -> () {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed

        let keypair = generate_keypair(&mut rng).unwrap();
        let secret_key_multibase = serialize_secret_key(&keypair.secret_key).unwrap();
        let public_key_multibase = serialize_public_key(&keypair.public_key).unwrap();
        println!("secret_key: {}", secret_key_multibase);
        println!("public_key: {}", public_key_multibase);

        assert!(true);
    }
}
