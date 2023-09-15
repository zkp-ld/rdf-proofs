use crate::{
    common::{BBSPlusHash, BBSPlusKeypair, BBSPlusParams, BBSPlusPublicKey, BBSPlusSecretKey},
    constants::GENERATOR_SEED,
    error::RDFProofsError,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
use multibase::Base;

pub fn generate_params(message_count: u32) -> BBSPlusParams {
    // Note: Parameters here are shared among all the issuers.
    BBSPlusParams::new::<BBSPlusHash>(GENERATOR_SEED, message_count)
}

pub fn generate_keypair<R: RngCore>(rng: &mut R) -> Result<BBSPlusKeypair, RDFProofsError> {
    // generate parameters to get `g_2` for generating public key in G2
    // Note: We do not need `h_i` here but `message_count` cannot be omitted so just set it `1`.
    let base_params = generate_params(1);

    Ok(BBSPlusKeypair::generate_using_rng(rng, &base_params))
}

pub fn serialize_secret_key(key: &BBSPlusSecretKey) -> Result<String, RDFProofsError> {
    let mut key_bytes = Vec::new();
    key.serialize_compressed(&mut key_bytes)?;
    Ok(multibase::encode(Base::Base64Url, key_bytes))
}

pub fn serialize_public_key(key: &BBSPlusPublicKey) -> Result<String, RDFProofsError> {
    let mut key_bytes = Vec::new();
    key.serialize_compressed(&mut key_bytes)?;
    Ok(multibase::encode(Base::Base64Url, key_bytes))
}

pub fn deserialize_secret_key(key: &str) -> Result<BBSPlusSecretKey, RDFProofsError> {
    let (_, key_bytes) = multibase::decode(key)?;
    Ok(BBSPlusSecretKey::deserialize_compressed(&*key_bytes)?)
}

pub fn deserialize_public_key(key: &str) -> Result<BBSPlusPublicKey, RDFProofsError> {
    let (_, key_bytes) = multibase::decode(key)?;
    Ok(BBSPlusPublicKey::deserialize_compressed(&*key_bytes)?)
}

#[cfg(test)]
mod tests {
    use super::generate_keypair;
    use crate::key_gen::{serialize_public_key, serialize_secret_key};
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
