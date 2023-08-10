use crate::{
    constants::{DELIMITER, MAP_TO_SCALAR_AS_HASH_DST},
    context::{DATA_INTEGRITY_PROOF, VERIFICATION_METHOD},
    error::RDFProofsError,
};
use ark_bls12_381::{Bls12_381, G1Affine};
use ark_ec::pairing::Pairing;
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use blake2::Blake2b512;
use oxrdf::{vocab::rdf::TYPE, Graph, NamedNodeRef, Term, TermRef};
use proof_system::proof::Proof;

pub type Fr = <Bls12_381 as Pairing>::ScalarField;
pub type ProofG1 = Proof<Bls12_381, G1Affine>;

pub fn get_hasher() -> DefaultFieldHasher<Blake2b512> {
    <DefaultFieldHasher<Blake2b512> as HashToField<Fr>>::new(MAP_TO_SCALAR_AS_HASH_DST)
}

pub fn hash_terms_to_field(
    terms: &Vec<Term>,
    hasher: &DefaultFieldHasher<Blake2b512>,
) -> Result<Vec<Fr>, RDFProofsError> {
    terms
        .iter()
        .map(|term| hash_term_to_field(term.as_ref(), hasher))
        .collect()
}

pub fn hash_term_to_field(
    term: TermRef,
    hasher: &DefaultFieldHasher<Blake2b512>,
) -> Result<Fr, RDFProofsError> {
    hasher
        .hash_to_field(term.to_string().as_bytes(), 1)
        .pop()
        .ok_or(RDFProofsError::HashToField)
}

pub fn get_delimiter() -> Result<Fr, RDFProofsError> {
    let hasher = get_hasher();
    hasher
        .hash_to_field(DELIMITER, 1)
        .pop()
        .ok_or(RDFProofsError::HashToField)
}

pub fn get_verification_method_identifier(
    proof_options: &Graph,
) -> Result<NamedNodeRef, RDFProofsError> {
    let proof_options_subject = proof_options
        .subject_for_predicate_object(TYPE, DATA_INTEGRITY_PROOF)
        .ok_or(RDFProofsError::InvalidProofConfiguration)?;
    let verification_method_identifier = proof_options
        .object_for_subject_predicate(proof_options_subject, VERIFICATION_METHOD)
        .ok_or(RDFProofsError::InvalidProofConfiguration)?;
    match verification_method_identifier {
        TermRef::NamedNode(v) => Ok(v),
        _ => Err(RDFProofsError::InvalidVerificationMethodURL),
    }
}
