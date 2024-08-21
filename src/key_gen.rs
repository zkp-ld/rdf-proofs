use crate::{
    common::{
        ark_to_base64url_with_codec, get_hasher, hash_byte_to_field, multibase_with_codec_to_ark,
        BBSPlusHash, BBSPlusKeypair, BBSPlusParams, Multicodec,
    },
    constants::{GENERATOR_SEED, PPID_PREFIX, PPID_SEED},
    error::RDFProofsError,
};
use ark_bls12_381::G1Affine;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_std::rand::RngCore;
use dock_crypto_utils::{concat_slices, hashing_utils::projective_group_elem_from_try_and_incr};

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

#[derive(Debug)]
pub struct PPID {
    pub ppid: G1Affine,
    pub domain: String,
    pub base: G1Affine,
}

impl PPID {
    pub fn new(secret: &[u8], domain: &str) -> Result<Self, RDFProofsError> {
        // secret
        let hasher = get_hasher();
        let secret_int = hash_byte_to_field(secret, &hasher)?;

        // base = H(domain)
        let base = Self::generate_base(domain)?;

        // ppid = H(domain)^secret
        let ppid = base.mul_bigint(secret_int.into_bigint());

        Ok(Self {
            ppid: ppid.into(),
            domain: domain.to_string(),
            base: base.into(),
        })
    }

    pub fn try_from_multibase(multibase: &str, domain: &str) -> Result<Self, RDFProofsError> {
        let ppid_multibase = multibase
            .strip_prefix(PPID_PREFIX)
            .ok_or(RDFProofsError::InvalidPPID)?;
        let (_, ppid) = multibase_with_codec_to_ark(ppid_multibase)?;
        let base = Self::generate_base(domain)?;

        Ok(Self {
            ppid,
            domain: domain.to_string(),
            base: base.into(),
        })
    }

    pub fn try_into_multibase(&self) -> Result<String, RDFProofsError> {
        let ppid_base64url = ark_to_base64url_with_codec(&self.ppid, Multicodec::Bls12381G1Pub)?;
        Ok(format!("{}{}", PPID_PREFIX, ppid_base64url))
    }

    fn generate_base(domain: &str) -> Result<G1Affine, RDFProofsError> {
        let base = projective_group_elem_from_try_and_incr::<G1Affine, BBSPlusHash>(
            &concat_slices!(PPID_SEED, domain.as_bytes()),
        );
        Ok(base.into())
    }
}

#[cfg(test)]
mod tests {
    use super::generate_keypair;
    use crate::{
        common::{ark_to_base58btc_with_codec, ark_to_base64url, Multicodec},
        key_gen::generate_params,
    };
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
    fn key_gen_base64url() -> () {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed

        let keypair = generate_keypair(&mut rng).unwrap();
        let secret_key = ark_to_base64url(&keypair.secret_key).unwrap();
        let public_key = ark_to_base64url(&keypair.public_key).unwrap();
        println!("secret_key: {}", secret_key);
        println!("public_key: {}", public_key);

        assert!(true);
    }

    #[test]
    fn key_gen_base58btc() -> () {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed

        let keypair = generate_keypair(&mut rng).unwrap();
        let secret_key =
            ark_to_base58btc_with_codec(&keypair.secret_key, Multicodec::Bls12381G2Priv).unwrap();
        let public_key =
            ark_to_base58btc_with_codec(&keypair.public_key, Multicodec::Bls12381G2Pub).unwrap();
        println!("secret_key: {}", secret_key);
        println!("public_key: {}", public_key);

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
