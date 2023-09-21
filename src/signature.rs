use crate::{
    common::{
        canonicalize_graph_into_terms, configure_proof_core, get_delimiter,
        get_graph_from_ntriples, get_hasher, get_vc_from_ntriples,
        get_verification_method_identifier, hash_byte_to_field, hash_terms_to_field,
        BBSPlusSignature, Fr,
    },
    constants::CRYPTOSUITE_SIGN,
    context::{DATA_INTEGRITY_PROOF, MULTIBASE, PROOF_VALUE},
    error::RDFProofsError,
    key_gen::generate_params,
    key_graph::KeyGraph,
    vc::VerifiableCredential,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
use multibase::Base;
use oxrdf::{vocab::rdf::TYPE, Graph, LiteralRef, Term, TripleRef};

pub fn sign<R: RngCore>(
    rng: &mut R,
    unsecured_credential: &mut VerifiableCredential,
    key_graph: &KeyGraph,
) -> Result<(), RDFProofsError> {
    let proof = sign_core(rng, unsecured_credential, key_graph)?;
    unsecured_credential.proof = proof;
    Ok(())
}

pub fn sign_string<R: RngCore>(
    rng: &mut R,
    document: &str,
    proof_option: &str,
    key_graph: &str,
) -> Result<String, RDFProofsError> {
    let unsecured_credential = get_vc_from_ntriples(document, proof_option)?;
    let key_graph = get_graph_from_ntriples(key_graph)?.into();
    let proof = sign_core(rng, &unsecured_credential, &key_graph)?;
    let result: String = proof
        .iter()
        .map(|t| format!("{} .\n", t.to_string()))
        .collect();
    Ok(result)
}

fn sign_core<R: RngCore>(
    rng: &mut R,
    unsecured_credential: &VerifiableCredential,
    key_graph: &KeyGraph,
) -> Result<Graph, RDFProofsError> {
    let VerifiableCredential {
        document,
        proof: proof_option,
    } = unsecured_credential;
    let transformed_data = transform(document)?;
    let proof_config = configure_proof(&proof_option)?;
    let canonical_proof_config = transform(&proof_config)?;
    let hash_data = hash(None, &transformed_data, &canonical_proof_config)?;
    let proof = serialize_proof(rng, &hash_data, &proof_config, key_graph)?;
    Ok(proof)
}

pub fn verify(
    secured_credential: &VerifiableCredential,
    key_graph: &KeyGraph,
) -> Result<(), RDFProofsError> {
    let VerifiableCredential { document, .. } = secured_credential;
    let proof_config = secured_credential.get_proof_config();
    let proof_value = secured_credential.get_proof_value()?;
    // TODO: validate proof_config
    let transformed_data = transform(document)?;
    let canonical_proof_config = transform(&proof_config)?;
    let hash_data = hash(None, &transformed_data, &canonical_proof_config)?;
    verify_base_proof(hash_data, &proof_value, &proof_config, key_graph)
}

pub fn verify_string(document: &str, proof: &str, key_graph: &str) -> Result<(), RDFProofsError> {
    // construct input for `verify` from string-based input
    let vc = get_vc_from_ntriples(document, proof)?;
    let key_graph = get_graph_from_ntriples(key_graph)?.into();

    verify(&vc, &key_graph)
}

pub(crate) fn transform(graph: &Graph) -> Result<Vec<Term>, RDFProofsError> {
    canonicalize_graph_into_terms(graph)
}

fn configure_proof(proof_options: &Graph) -> Result<Graph, RDFProofsError> {
    configure_proof_core(proof_options, CRYPTOSUITE_SIGN)
}

pub(crate) fn hash(
    secret: Option<&[u8]>,
    transformed_document: &Vec<Term>,
    canonical_proof_config: &Vec<Term>,
) -> Result<Vec<Fr>, RDFProofsError> {
    let hasher = get_hasher();

    let secret = match secret {
        Some(s) => hash_byte_to_field(s, &hasher)?,
        None => Fr::from(1),
    };
    let mut hashed_document = hash_terms_to_field(transformed_document, &hasher)?;
    let mut hashed_proof = hash_terms_to_field(canonical_proof_config, &hasher)?;
    let delimiter = get_delimiter()?;

    let mut result =
        Vec::with_capacity(transformed_document.len() + canonical_proof_config.len() + 1);

    result.push(secret);
    result.append(&mut hashed_document);
    result.push(delimiter);
    result.append(&mut hashed_proof);
    Ok(result)
}

fn serialize_proof<R: RngCore>(
    rng: &mut R,
    hash_data: &Vec<Fr>,
    proof_options: &Graph,
    key_graph: &KeyGraph,
) -> Result<Graph, RDFProofsError> {
    let message_count = hash_data
        .len()
        .try_into()
        .map_err(|_| RDFProofsError::MessageSizeOverflow)?;
    let params = generate_params(message_count);

    let verification_method_identifier = get_verification_method_identifier(proof_options)?;
    let (secret_key, _public_key) = key_graph.get_keypair(verification_method_identifier)?;

    let signature = BBSPlusSignature::new(rng, hash_data, &secret_key, &params)?;

    let mut signature_bytes = Vec::new();
    signature.serialize_compressed(&mut signature_bytes)?;
    let signature_base64url = multibase::encode(Base::Base64Url, signature_bytes);

    let mut result = proof_options.clone();
    let proof_subject = proof_options
        .subject_for_predicate_object(TYPE, DATA_INTEGRITY_PROOF)
        .ok_or(RDFProofsError::InvalidProofConfiguration)?;
    result.insert(TripleRef::new(
        proof_subject,
        PROOF_VALUE,
        LiteralRef::new_typed_literal(&signature_base64url, MULTIBASE),
    ));

    Ok(result)
}

pub(crate) fn verify_base_proof(
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
