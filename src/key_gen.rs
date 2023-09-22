use crate::{
    common::{BBSPlusHash, BBSPlusKeypair, BBSPlusParams},
    constants::GENERATOR_SEED,
    error::RDFProofsError,
};
use ark_std::rand::RngCore;

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

#[cfg(test)]
mod tests {
    use super::generate_keypair;
    use crate::{common::ark_to_base64url, key_gen::generate_params};
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn params_gen_success() {
        let params1 = generate_params(1);
        let params2 = generate_params(2);
        let params3 = generate_params(3);
        println!("{:#?}", params1);
        println!("{:#?}", params2);
        println!("{:#?}", params3);
    }

    #[test]
    fn key_gen_simple() -> () {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed

        let keypair = generate_keypair(&mut rng).unwrap();
        let secret_key_multibase = ark_to_base64url(&keypair.secret_key).unwrap();
        let public_key_multibase = ark_to_base64url(&keypair.public_key).unwrap();
        println!("secret_key: {}", secret_key_multibase);
        println!("public_key: {}", public_key_multibase);

        assert!(true);
    }

    #[test]
    fn key_gen_success() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let keypair1 = generate_keypair(&mut rng);
        let keypair2 = generate_keypair(&mut rng);
        let keypair3 = generate_keypair(&mut rng);
        assert!(keypair1.is_ok());
        assert!(keypair2.is_ok());
        assert!(keypair3.is_ok());
    }
}
