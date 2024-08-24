use crate::{
    common::{
        ark_to_base58btc, get_hasher, hash_byte_to_field, multibase_with_codec_to_ark, BBSPlusHash,
        BBSPlusKeypair, BBSPlusParams, Multicodec,
    },
    constants::{DID_KEY_PREFIX, GENERATOR_SEED, PPID_SEED},
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
pub struct KeyPairBase58Btc {
    pub secret_key: String,
    pub public_key: String,
}

impl KeyPairBase58Btc {
    pub fn new<R: RngCore>(rng: &mut R) -> Result<Self, RDFProofsError> {
        let keypair = generate_keypair(rng)?;
        let secret_key = ark_to_base58btc(&keypair.secret_key, Multicodec::Bls12381G2Priv)?;
        let public_key = ark_to_base58btc(&keypair.public_key, Multicodec::Bls12381G2Pub)?;

        Ok(Self {
            secret_key,
            public_key,
        })
    }
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

    pub fn try_from_did_key(did_key: &str, domain: &str) -> Result<Self, RDFProofsError> {
        let ppid_multibase = did_key
            .strip_prefix(DID_KEY_PREFIX)
            .ok_or(RDFProofsError::InvalidPPID)?;
        let (_, ppid) = multibase_with_codec_to_ark(ppid_multibase)?;
        let base = Self::generate_base(domain)?;

        Ok(Self {
            ppid,
            domain: domain.to_string(),
            base: base.into(),
        })
    }

    pub fn try_into_did_key(&self) -> Result<String, RDFProofsError> {
        let ppid_base58btc = ark_to_base58btc(&self.ppid, Multicodec::Bls12381G1Pub)?;
        Ok(format!("{}{}", DID_KEY_PREFIX, ppid_base58btc))
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
    use crate::{key_gen::generate_params, KeyPairBase58Btc};
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
    fn key_gen_base58btc() -> () {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed

        let keypair = KeyPairBase58Btc::new(&mut rng).unwrap();
        println!("secret_key: {}", keypair.secret_key);
        println!("public_key: {}", keypair.public_key);

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
