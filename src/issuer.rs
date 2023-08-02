use crate::{error::SignError, vc::VerifiableCredential};
use oxrdf::{Graph, Term};

pub fn sign(
    unsecured_credential: &VerifiableCredential,
) -> Result<VerifiableCredential, SignError> {
    let VerifiableCredential { document, proof } = unsecured_credential;
    let transformed_document = transform(document);
    let canonical_proof_config = configure_proof(proof);
    let hash_data = hash(transformed_document, canonical_proof_config);
    let proof_value = serialize_proof(hash_data, proof);
    Ok(add_proof_value(unsecured_credential, proof_value))
}

fn transform(unsecured_document: &Graph) -> Vec<Term> {
    todo!();
}

fn configure_proof(proof_options: &Graph) -> Vec<Term> {
    todo!();
}

fn hash(transformed_document: Vec<Term>, canonical_proof_config: Vec<Term>) -> Vec<String> {
    todo!();
}

fn serialize_proof(hash_data: Vec<String>, proof_options: &Graph) -> String {
    todo!();
}

fn add_proof_value(
    unsecured_credential: &VerifiableCredential,
    proof_value: String,
) -> VerifiableCredential {
    todo!();
}
