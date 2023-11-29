mod assign_uid_signature;
mod blind_signature;
mod common;
mod constants;
pub mod context;
mod derive_proof;
mod elgamal;
mod elliptic_elgamal;
pub mod error;
pub mod key_gen;
mod key_graph;
mod ordered_triple;
mod predicate;
mod signature;
mod vc;
mod verify_proof;

pub use blind_signature::{
    blind_sign, blind_sign_string, blind_verify, blind_verify_string, request_blind_sign,
    request_blind_sign_string, unblind, unblind_string, verify_blind_sign_request,
    verify_blind_sign_request_string, BlindSignRequest, BlindSignRequestString,
};
pub use common::{ark_to_base64url, ark_to_multibase, multibase_to_ark};
pub use derive_proof::{derive_proof, derive_proof_string};
pub use elgamal::{
    elgamal_decrypt, elgamal_encrypt, elgamal_keygen, ElGamalCiphertext, ElGamalPublicKey,
    ElGamalSecretKey,
};
pub use elliptic_elgamal::{
    elliptic_elgamal_decrypt, elliptic_elgamal_encrypt, elliptic_elgamal_keygen,
    elliptic_elgamal_verifiable_encryption_with_bbs_plus,
    verify_elliptic_elgamal_verifiable_encryption_with_bbs_plus,
};
pub use key_graph::KeyGraph;
pub use predicate::CircuitString;
pub use signature::{sign, sign_string, verify, verify_string};
pub use vc::{VcPair, VcPairString, VerifiableCredential};
pub use verify_proof::{verify_proof, verify_proof_string};
