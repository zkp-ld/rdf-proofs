use crate::{
    common::{
        get_delimiter, get_graph_from_ntriples_str, get_hasher, get_verification_method_identifier,
        hash_terms_to_field, Fr,
    },
    constants::CRYPTOSUITE_SIGN,
    context::{CREATED, CRYPTOSUITE, DATA_INTEGRITY_PROOF, MULTIBASE, PROOF_VALUE},
    error::RDFProofsError,
    key_gen::generate_params,
    key_graph::KeyGraph,
    vc::VerifiableCredential,
};
use ark_bls12_381::Bls12_381;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
use bbs_plus::prelude::SignatureG1 as BBSSignatureG1;
use multibase::Base;
use oxrdf::{
    vocab::{self, rdf::TYPE},
    Graph, Literal, Term, TermRef, Triple,
};
use oxsdatatypes::DateTime;
use std::str::FromStr;

pub fn sign<R: RngCore>(
    rng: &mut R,
    unsecured_credential: &mut VerifiableCredential,
    key_graph: &KeyGraph,
) -> Result<(), RDFProofsError> {
    let VerifiableCredential { document, proof } = unsecured_credential;
    let transformed_data = transform(document, proof)?;
    let canonical_proof_config = configure_proof(proof)?;
    let hash_data = hash(&transformed_data, &canonical_proof_config)?;
    let proof_value = serialize_proof(rng, &hash_data, proof, key_graph)?;
    add_proof_value(unsecured_credential, proof_value)?;
    Ok(())
}

pub fn sign_string<R: RngCore>(
    rng: &mut R,
    document: &str,
    proof: &str,
    key_graph: &str,
) -> Result<String, RDFProofsError> {
    // construct input for `sign` from string-based input
    let document = get_graph_from_ntriples_str(document)?;
    let proof = get_graph_from_ntriples_str(proof)?;
    let key_graph = get_graph_from_ntriples_str(key_graph)?.into();
    let mut vc = VerifiableCredential::new(document, proof);

    sign(rng, &mut vc, &key_graph)?;

    // return proofValue as String
    let proof_value_triple = vc
        .proof
        .triples_for_predicate(PROOF_VALUE)
        .next()
        .ok_or(RDFProofsError::Other("internal error".to_string()))?;
    match proof_value_triple.object {
        oxrdf::TermRef::Literal(v) => Ok(v.value().to_string()),
        _ => Err(RDFProofsError::Other("internal error".to_string())),
    }
}

pub fn verify(
    secured_credential: &VerifiableCredential,
    key_graph: &KeyGraph,
) -> Result<(), RDFProofsError> {
    let VerifiableCredential { document, proof } = secured_credential;
    let proof_value_triple = proof
        .triples_for_predicate(PROOF_VALUE)
        .next()
        .ok_or(RDFProofsError::MalformedProof)?;
    let proof_value = match proof_value_triple.object {
        TermRef::Literal(v) => v.value(),
        _ => return Err(RDFProofsError::MalformedProof),
    };
    let proof_config = Graph::from_iter(
        proof
            .iter()
            .filter(|t| t.predicate != PROOF_VALUE)
            .collect::<Vec<_>>(),
    );
    // TODO: validate proof_config
    let transformed_data = transform(document, proof)?;
    let canonical_proof_config = configure_proof(&proof_config)?;
    let hash_data = hash(&transformed_data, &canonical_proof_config)?;
    verify_base_proof(hash_data, proof_value, &proof_config, key_graph)
}

pub fn verify_string(document: &str, proof: &str, key_graph: &str) -> Result<(), RDFProofsError> {
    // construct input for `verify` from string-based input
    let document = get_graph_from_ntriples_str(document)?;
    let proof = get_graph_from_ntriples_str(proof)?;
    let key_graph = get_graph_from_ntriples_str(key_graph)?.into();
    let vc = VerifiableCredential::new(document, proof);

    verify(&vc, &key_graph)
}

fn transform(
    unsecured_document: &Graph,
    _proof_options: &Graph,
) -> Result<Vec<Term>, RDFProofsError> {
    _canonicalize_into_terms(unsecured_document)
}

fn configure_proof(proof_options: &Graph) -> Result<Vec<Term>, RDFProofsError> {
    // if `proof_options.type` is not set to `DataIntegrityProof`
    // and `proof_options.cryptosuite` is not set to `bbs-termwise-signature-2023`
    // then `INVALID_PROOF_CONFIGURATION_ERROR` must be raised
    let proof_options_subject = proof_options
        .subject_for_predicate_object(TYPE, DATA_INTEGRITY_PROOF)
        .ok_or(RDFProofsError::InvalidProofConfiguration)?;
    let cryptosuite = proof_options
        .object_for_subject_predicate(proof_options_subject, CRYPTOSUITE)
        .ok_or(RDFProofsError::InvalidProofConfiguration)?;
    if let TermRef::Literal(v) = cryptosuite {
        if v.value() != CRYPTOSUITE_SIGN {
            return Err(RDFProofsError::InvalidProofConfiguration);
        }
    } else {
        return Err(RDFProofsError::InvalidProofConfiguration);
    }

    // if `proof_options.created` is not a valid xsd:dateTime,
    // `INVALID_PROOF_DATETIME_ERROR` must be raised
    let created = proof_options
        .object_for_subject_predicate(proof_options_subject, CREATED)
        .ok_or(RDFProofsError::InvalidProofDatetime)?;
    match created {
        TermRef::Literal(v) => {
            let (datetime, typ, _) = v.destruct();
            if DateTime::from_str(datetime).is_err()
                || !typ.is_some_and(|t| t == vocab::xsd::DATE_TIME)
            {
                return Err(RDFProofsError::InvalidProofDatetime);
            }
        }
        _ => return Err(RDFProofsError::InvalidProofDatetime),
    }

    _canonicalize_into_terms(proof_options)
}

fn _canonicalize_into_terms(graph: &Graph) -> Result<Vec<Term>, RDFProofsError> {
    let issued_identifiers_map = &rdf_canon::issue_graph(graph)?;
    let canonicalized_graph = rdf_canon::relabel_graph(graph, issued_identifiers_map)?;
    let canonicalized_triples = rdf_canon::sort_graph(&canonicalized_graph);
    Ok(canonicalized_triples
        .into_iter()
        .flat_map(|t| vec![t.subject.into(), t.predicate.into(), t.object])
        .collect())
}

fn hash(
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
    let message_count = hash_data.len();

    let verification_method_identifier = get_verification_method_identifier(proof_options)?;
    let (secret_key, _public_key) = key_graph.get_keypair(verification_method_identifier)?;

    let params = generate_params(message_count);

    let signature = BBSSignatureG1::<Bls12_381>::new(rng, hash_data, &secret_key, &params)?;

    let mut signature_bytes = Vec::new();
    signature.serialize_compressed(&mut signature_bytes)?;
    let signature_base64url = multibase::encode(Base::Base64Url, signature_bytes);

    Ok(signature_base64url)
}

fn add_proof_value(
    unsecured_credential: &mut VerifiableCredential,
    proof_value: String,
) -> Result<(), RDFProofsError> {
    let VerifiableCredential { proof, .. } = unsecured_credential;
    let proof_subject = proof
        .subject_for_predicate_object(vocab::rdf::TYPE, DATA_INTEGRITY_PROOF)
        .ok_or(RDFProofsError::InvalidProofConfiguration)?;
    proof.insert(&Triple::new(
        proof_subject,
        PROOF_VALUE,
        Literal::new_typed_literal(proof_value, MULTIBASE),
    ));
    Ok(())
}

fn verify_base_proof(
    hash_data: Vec<Fr>,
    proof_value: &str,
    proof_config: &Graph,
    key_graph: &KeyGraph,
) -> Result<(), RDFProofsError> {
    let (_, proof_value_bytes) = multibase::decode(proof_value)?;
    let signature = BBSSignatureG1::<Bls12_381>::deserialize_compressed(&*proof_value_bytes)?;
    let verification_method_identifier = get_verification_method_identifier(proof_config)?;
    let pk = key_graph.get_public_key(verification_method_identifier)?;
    let params = generate_params(hash_data.len());
    Ok(signature.verify(&hash_data, pk, params)?)
}
