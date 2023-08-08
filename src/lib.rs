use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;

pub mod context;
pub mod error;
pub mod keygen;
pub mod proof;
pub mod signature;
pub mod vc;

pub mod constants {
    pub const CRYPTOSUITE_SIGN: &str = "bbs-termwise-signature-2023";
    pub const CRYPTOSUITE_PROOF: &str = "bbs-termwise-proof-2023";
    pub const NYM_IRI_PREFIX: &str = "urn:nym:";
    pub const GENERATOR_SEED: &[u8; 28] = b"BBS_*_MESSAGE_GENERATOR_SEED"; // TODO: fix it later
    pub const MAP_TO_SCALAR_AS_HASH_DST: &[u8; 32] = b"BBS_*_MAP_MSG_TO_SCALAR_AS_HASH_"; // TODO: fix it later
    pub const DELIMITER: &[u8; 13] = b"__DELIMITER__"; // TODO: fix it later
}

type Fr = <Bls12_381 as Pairing>::ScalarField;
