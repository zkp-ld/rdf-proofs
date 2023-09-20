use crate::{
    common::{
        canonicalize_graph_into_terms, configure_proof_core, get_delimiter,
        get_graph_from_ntriples, get_hasher, get_vc_from_ntriples,
        get_verification_method_identifier, hash_terms_to_field, BBSPlusSignature, Fr,
    },
    constants::CRYPTOSUITE_SIGN,
    error::RDFProofsError,
    key_gen::generate_params,
    key_graph::KeyGraph,
    vc::VerifiableCredential,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
use multibase::Base;
use oxrdf::{Graph, Term};

pub fn sign<R: RngCore>(
    rng: &mut R,
    unsecured_credential: &mut VerifiableCredential,
    key_graph: &KeyGraph,
) -> Result<(), RDFProofsError> {
    let proof_value = sign_core(rng, unsecured_credential, key_graph)?;
    unsecured_credential.add_proof_value(proof_value)?;
    Ok(())
}

pub fn sign_string<R: RngCore>(
    rng: &mut R,
    document: &str,
    proof: &str,
    key_graph: &str,
) -> Result<String, RDFProofsError> {
    let unsecured_credential = get_vc_from_ntriples(document, proof)?;
    let key_graph = get_graph_from_ntriples(key_graph)?.into();
    let proof_value = sign_core(rng, &unsecured_credential, &key_graph)?;
    Ok(proof_value)
}

fn sign_core<R: RngCore>(
    rng: &mut R,
    unsecured_credential: &VerifiableCredential,
    key_graph: &KeyGraph,
) -> Result<String, RDFProofsError> {
    let VerifiableCredential { document, proof } = unsecured_credential;
    let transformed_data = transform(document, proof)?;
    let canonical_proof_config = configure_proof(proof)?;
    let hash_data = hash(&transformed_data, &canonical_proof_config)?;
    let proof_value = serialize_proof(rng, &hash_data, proof, key_graph)?;
    Ok(proof_value)
}

pub fn verify(
    secured_credential: &VerifiableCredential,
    key_graph: &KeyGraph,
) -> Result<(), RDFProofsError> {
    let VerifiableCredential { document, proof } = secured_credential;
    let proof_config = secured_credential.get_proof_config();
    let proof_value = secured_credential.get_proof_value()?;
    // TODO: validate proof_config
    let transformed_data = transform(document, proof)?;
    let canonical_proof_config = configure_proof(&proof_config)?;
    let hash_data = hash(&transformed_data, &canonical_proof_config)?;
    verify_base_proof(hash_data, &proof_value, &proof_config, key_graph)
}

pub fn verify_string(document: &str, proof: &str, key_graph: &str) -> Result<(), RDFProofsError> {
    // construct input for `verify` from string-based input
    let vc = get_vc_from_ntriples(document, proof)?;
    let key_graph = get_graph_from_ntriples(key_graph)?.into();

    verify(&vc, &key_graph)
}

pub(crate) fn transform(
    unsecured_document: &Graph,
    _proof_options: &Graph,
) -> Result<Vec<Term>, RDFProofsError> {
    canonicalize_graph_into_terms(unsecured_document)
}

fn configure_proof(proof_options: &Graph) -> Result<Vec<Term>, RDFProofsError> {
    configure_proof_core(proof_options, CRYPTOSUITE_SIGN)
}

pub(crate) fn hash(
    transformed_document: &Vec<Term>,
    canonical_proof_config: &Vec<Term>,
) -> Result<Vec<Fr>, RDFProofsError> {
    let hasher = get_hasher();
    let mut hashed_document = hash_terms_to_field(transformed_document, &hasher)?;
    let mut hashed_proof = hash_terms_to_field(canonical_proof_config, &hasher)?;
    let delimiter = get_delimiter()?;
    hashed_document.push(delimiter);
    hashed_document.append(&mut hashed_proof);
    Ok(hashed_document)
}

fn serialize_proof<R: RngCore>(
    rng: &mut R,
    hash_data: &Vec<Fr>,
    proof_options: &Graph,
    key_graph: &KeyGraph,
) -> Result<String, RDFProofsError> {
    let message_count = hash_data
        .len()
        .try_into()
        .map_err(|_| RDFProofsError::MessageSizeOverflow)?;

    let verification_method_identifier = get_verification_method_identifier(proof_options)?;
    let (secret_key, _public_key) = key_graph.get_keypair(verification_method_identifier)?;

    let params = generate_params(message_count);

    let signature = BBSPlusSignature::new(rng, hash_data, &secret_key, &params)?;

    let mut signature_bytes = Vec::new();
    signature.serialize_compressed(&mut signature_bytes)?;
    let signature_base64url = multibase::encode(Base::Base64Url, signature_bytes);

    Ok(signature_base64url)
}

fn verify_base_proof(
    hash_data: Vec<Fr>,
    proof_value: &str,
    proof_config: &Graph,
    key_graph: &KeyGraph,
) -> Result<(), RDFProofsError> {
    let (_, proof_value_bytes) = multibase::decode(proof_value)?;
    let signature = BBSPlusSignature::deserialize_compressed(&*proof_value_bytes)?;
    let verification_method_identifier = get_verification_method_identifier(proof_config)?;
    let pk = key_graph.get_public_key(verification_method_identifier)?;
    let params = generate_params(
        hash_data
            .len()
            .try_into()
            .map_err(|_| RDFProofsError::MessageSizeOverflow)?,
    );
    Ok(signature.verify(&hash_data, pk, params)?)
}
