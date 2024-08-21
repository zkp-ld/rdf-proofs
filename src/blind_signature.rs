use crate::{
    common::{
        ark_to_base64url, configure_proof_core, get_graph_from_ntriples, get_hasher,
        get_vc_from_ntriples, get_verification_method_identifier, hash_byte_to_field,
        multibase_to_ark, BBSPlusSignature, Fr, Proof, Statements,
    },
    constants::{BLIND_SIG_REQUEST_CONTEXT, CRYPTOSUITE_BOUND_SIGN},
    context::{DATA_INTEGRITY_PROOF, MULTIBASE, PROOF_VALUE},
    error::RDFProofsError,
    key_gen::generate_params,
    signature::{hash, transform, verify_base_proof},
    KeyGraph, VerifiableCredential,
};
use ark_bls12_381::G1Affine;
use ark_std::{rand::RngCore, UniformRand};
use blake2::Blake2b512;
use oxrdf::{vocab::rdf::TYPE, Graph, LiteralRef, TripleRef};
use proof_system::{
    prelude::MetaStatements,
    proof_spec::ProofSpec,
    statement::ped_comm::PedersenCommitment,
    witness::{Witness, Witnesses},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug)]
pub struct BlindSignRequest {
    pub commitment: G1Affine,
    pub blinding: Fr,
    pub pok_for_commitment: Option<Proof>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlindSignRequestString {
    pub commitment: String,
    pub blinding: String,
    #[serde(rename = "pokForCommitment")]
    pub pok_for_commitment: Option<String>,
}

pub fn request_blind_sign<R: RngCore>(
    rng: &mut R,
    secret: &[u8],
    challenge: Option<&str>,
    skip_pok: Option<bool>,
) -> Result<BlindSignRequest, RDFProofsError> {
    // bases := [h_0, h[0]]
    let params = generate_params(1);
    let bases = vec![params.h_0, params.h[0]];

    // blinding to be used in commitment
    let blinding = Fr::rand(rng);

    // secret_int to be committed
    let hasher = get_hasher();
    let secret_int = hash_byte_to_field(secret, &hasher)?;

    // commitment := h_0^{blinding} * h[0]^{secret_int}
    let committed_secret = BTreeMap::from([(0_usize, &secret_int)]);
    let commitment = params.commit_to_messages(committed_secret, &blinding)?;

    let skip_pok = match skip_pok {
        Some(v) => v,
        None => false,
    };

    // skip Proof of Knowledge if skip_pok == true or None
    if skip_pok {
        return Ok(BlindSignRequest {
            commitment,
            blinding,
            pok_for_commitment: None,
        });
    }

    // statements := [bases, commitment]
    let mut statements = Statements::new();
    statements.add(PedersenCommitment::new_statement_from_params(
        bases, commitment,
    ));

    // proof_spec := [statements, meta_statements, _, context]
    let context = Some(BLIND_SIG_REQUEST_CONTEXT.to_vec());
    let proof_spec = ProofSpec::new(statements, MetaStatements::new(), vec![], context);
    proof_spec.validate()?;

    // witnesses := [blinding, secret_int]
    let committed_msgs = vec![blinding, secret_int];
    let mut witnesses = Witnesses::new();
    witnesses.add(Witness::PedersenCommitment(committed_msgs));

    // challenge
    let challenge = challenge.map(|v| v.as_bytes().to_vec());

    // proof := NIZK{witnesses: proof_spec}(challenge)
    let pok_for_commitment =
        Proof::new::<R, Blake2b512>(rng, proof_spec, witnesses, challenge, Default::default())?.0;

    Ok(BlindSignRequest {
        commitment,
        blinding,
        pok_for_commitment: Some(pok_for_commitment),
    })
}

pub fn request_blind_sign_string<R: RngCore>(
    rng: &mut R,
    secret: &[u8],
    challenge: Option<&str>,
    skip_pok: Option<bool>,
) -> Result<BlindSignRequestString, RDFProofsError> {
    let BlindSignRequest {
        commitment,
        blinding,
        pok_for_commitment,
    } = request_blind_sign(rng, secret, challenge, skip_pok)?;
    let commitment_base64url = ark_to_base64url(&commitment)?;

    let pok_for_commitment_base64url = if let Some(v) = pok_for_commitment {
        Some(ark_to_base64url(&v)?)
    } else {
        None
    };

    let blinding_base64url = ark_to_base64url(&blinding)?;
    Ok(BlindSignRequestString {
        commitment: commitment_base64url,
        pok_for_commitment: pok_for_commitment_base64url,
        blinding: blinding_base64url,
    })
}

pub fn verify_blind_sign_request<R: RngCore>(
    rng: &mut R,
    commitment: &G1Affine,
    pok_for_commitment: Proof,
    challenge: Option<&str>,
) -> Result<(), RDFProofsError> {
    // bases := [h_0, h[0], h[1], ...]
    let params = generate_params(1);
    let mut bases = vec![params.h_0];
    bases.push(params.h[0]);

    // statements := [bases, commitment]
    let mut statements = Statements::new();
    statements.add(PedersenCommitment::new_statement_from_params(
        bases,
        commitment.clone(),
    ));

    // proof_spec := [statements, meta_statements, _, context]
    let context = Some(BLIND_SIG_REQUEST_CONTEXT.to_vec());
    let proof_spec = ProofSpec::new(statements, MetaStatements::new(), vec![], context);
    proof_spec.validate()?;

    // challenge
    let challenge = challenge.map(|v| v.as_bytes().to_vec());

    // verify
    Ok(pok_for_commitment.verify::<R, Blake2b512>(
        rng,
        proof_spec,
        challenge,
        Default::default(),
    )?)
}

pub fn verify_blind_sign_request_string<R: RngCore>(
    rng: &mut R,
    commitment: &str,
    pok_for_commitment: &str,
    challenge: Option<&str>,
) -> Result<(), RDFProofsError> {
    let commitment = multibase_to_ark(commitment)?;
    let pok_for_commitment = multibase_to_ark(pok_for_commitment)?;
    verify_blind_sign_request(rng, &commitment, pok_for_commitment, challenge)
}

pub fn blind_sign<R: RngCore>(
    rng: &mut R,
    commitment: &G1Affine,
    unsecured_credential: &mut VerifiableCredential,
    key_graph: &KeyGraph,
) -> Result<(), RDFProofsError> {
    let proof = blind_sign_core(rng, commitment, unsecured_credential, key_graph)?;
    unsecured_credential.proof = proof;
    Ok(())
}

pub fn blind_sign_string<R: RngCore>(
    rng: &mut R,
    commitment: &str,
    document: &str,
    proof_options: &str,
    key_graph: &str,
) -> Result<String, RDFProofsError> {
    let unsecured_credential = get_vc_from_ntriples(document, proof_options)?;
    let key_graph = get_graph_from_ntriples(key_graph)?.into();
    let proof = blind_sign_core(
        rng,
        &multibase_to_ark(commitment)?,
        &unsecured_credential,
        &key_graph,
    )?;
    let result: String = proof
        .iter()
        .map(|t| format!("{} .\n", t.to_string()))
        .collect();
    Ok(result)
}

fn blind_sign_core<R: RngCore>(
    rng: &mut R,
    commitment: &G1Affine,
    unsecured_credential: &VerifiableCredential,
    key_graph: &KeyGraph,
) -> Result<Graph, RDFProofsError> {
    let VerifiableCredential { document, proof } = unsecured_credential;
    let transformed_data = transform(document)?;
    let proof_config = configure_proof(proof)?;
    let canonical_proof_config = transform(&proof_config)?;
    let hash_data = hash(None, &transformed_data, &canonical_proof_config)?;
    let proof_value = serialize_proof_with_committed_messages(
        rng,
        commitment,
        &hash_data,
        &proof_config,
        key_graph,
    )?;

    Ok(proof_value)
}

fn configure_proof(proof_options: &Graph) -> Result<Graph, RDFProofsError> {
    configure_proof_core(proof_options, CRYPTOSUITE_BOUND_SIGN)
}

fn serialize_proof_with_committed_messages<R: RngCore>(
    rng: &mut R,
    commitment: &G1Affine,
    hash_data: &Vec<Fr>,
    proof_options: &Graph,
    key_graph: &KeyGraph,
) -> Result<Graph, RDFProofsError> {
    let message_count: u32 = hash_data
        .len()
        .try_into()
        .map_err(|_| RDFProofsError::MessageSizeOverflow)?;
    let params = generate_params(message_count);

    let verification_method_identifier = get_verification_method_identifier(proof_options)?;
    let (secret_key, _public_key) = key_graph.get_keypair(verification_method_identifier)?;

    // holder secret: m[0]
    // uncommitted messsage: m[1], m[2], ..., m[message_count]
    let mut uncommitted_messages = hash_data
        .iter()
        .enumerate()
        .map(|(i, m)| (i, m))
        .collect::<BTreeMap<_, _>>();
    // remove placeholder for secret as it will be given as commitment below
    uncommitted_messages.remove(&0);

    let blinded_signature = BBSPlusSignature::new_with_committed_messages(
        rng,
        commitment,
        uncommitted_messages,
        &secret_key,
        &params,
    )?;
    let blinded_signature_base64url = ark_to_base64url(&blinded_signature)?;

    let mut result = proof_options.clone();
    let proof_subject = proof_options
        .subject_for_predicate_object(TYPE, DATA_INTEGRITY_PROOF)
        .ok_or(RDFProofsError::InvalidProofConfiguration)?;
    result.insert(TripleRef::new(
        proof_subject,
        PROOF_VALUE,
        LiteralRef::new_typed_literal(&blinded_signature_base64url, MULTIBASE),
    ));

    Ok(result)
}

pub fn unblind(
    blinded_credential: &mut VerifiableCredential,
    blinding: &Fr,
) -> Result<(), RDFProofsError> {
    let proof_value = unblind_core(blinded_credential, blinding)?;
    blinded_credential.replace_proof_value(proof_value)?;
    Ok(())
}

pub fn unblind_string(
    document: &str,
    proof: &str,
    blinding: &str,
) -> Result<String, RDFProofsError> {
    let blinding = multibase_to_ark(blinding)?;
    let mut blinded_credential = get_vc_from_ntriples(document, proof)?;
    let proof_value = unblind_core(&blinded_credential, &blinding)?;
    blinded_credential.replace_proof_value(proof_value)?;
    let unblinded_proof: String = blinded_credential
        .proof
        .iter()
        .map(|t| format!("{} . \n", t.to_string()))
        .collect();
    Ok(unblinded_proof)
}

fn unblind_core(
    blinded_credential: &VerifiableCredential,
    blinding: &Fr,
) -> Result<String, RDFProofsError> {
    let proof_value = blinded_credential.get_proof_value()?;
    let blinded_signature: BBSPlusSignature = multibase_to_ark(&proof_value)?;
    let signature = blinded_signature.unblind(blinding);
    let signature_base64url = ark_to_base64url(&signature)?;
    Ok(signature_base64url)
}

pub fn blind_verify(
    secret: &[u8],
    secured_credential: &VerifiableCredential,
    key_graph: &KeyGraph,
) -> Result<(), RDFProofsError> {
    let VerifiableCredential { document, .. } = secured_credential;
    let proof_config = secured_credential.get_proof_config();
    let proof_value = secured_credential.get_proof_value()?;
    // TODO: validate proof_config
    let transformed_data = transform(document)?;
    let canonical_proof_config = transform(&proof_config)?;
    let hash_data = hash(Some(secret), &transformed_data, &canonical_proof_config)?;
    verify_base_proof(hash_data, &proof_value, &proof_config, key_graph)
}

pub fn blind_verify_string(
    secret: &[u8],
    document: &str,
    proof: &str,
    key_graph: &str,
) -> Result<(), RDFProofsError> {
    let vc = get_vc_from_ntriples(document, proof)?;
    let key_graph = get_graph_from_ntriples(key_graph)?.into();
    blind_verify(secret, &vc, &key_graph)
}

#[cfg(test)]
mod tests {
    use crate::{
        blind_sign, blind_sign_string, blind_verify, blind_verify_string,
        common::get_graph_from_ntriples, context::PROOF_VALUE, error::RDFProofsError,
        request_blind_sign, request_blind_sign_string, unblind, unblind_string,
        verify_blind_sign_request, verify_blind_sign_request_string, KeyGraph,
        VerifiableCredential,
    };
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    const KEY_GRAPH: &str = r#"
    # issuer0
    <did:example:issuer0> <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
    <did:example:issuer0#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
    <did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer0> .
    <did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "uekl-7abY7R84yTJEJ6JRqYohXxPZPDoTinJ7XCcBkmk" .
    <did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "ukiiQxfsSfV0E2QyBlnHTK2MThnd7_-Fyf6u76BUd24uxoDF4UjnXtxUo8b82iuPZBOa8BXd1NpE20x3Rfde9udcd8P8nPVLr80Xh6WLgI9SYR6piNzbHhEVIfgd_Vo9P" .
    # issuer1
    <did:example:issuer1> <https://w3id.org/security#verificationMethod> <did:example:issuer1#bls12_381-g2-pub001> .
    <did:example:issuer1#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
    <did:example:issuer1#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer1> .
    <did:example:issuer1#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "uQkpZn0SW42c2tlYa0IIFXyabAYHbwc0z3l_GvXQbWSg" .
    <did:example:issuer1#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "usFM3CcvBMl_Dg5ixhQkHKGdqzY3GU9Uck6lj2i8vpbzLFOiZnjDNOpsItrkbNf2iCku-SZu5kO3nbLis-fuRhz_QwFcKw9IBpbPRPwXNQTX3zzcFsoNzs_wo8tkLQlcS" .
    # issuer2
    <did:example:issuer2> <https://w3id.org/security#verificationMethod> <did:example:issuer2#bls12_381-g2-pub001> .
    <did:example:issuer2#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
    <did:example:issuer2#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer2> .
    <did:example:issuer2#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "u4nmBsiSwvHj7i_gBu1L6Cug0OXXhVPF6NWLfkQbCZiU" .
    <did:example:issuer2#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "uo_yMZWlZwQzLqEe6hEsORbsV5cSHQEQHNI0EOe_eUJdHsgCRxtpWMcxxcdshH5pAAUxt_ni6_cQCud3CdMcjAUN8yOvzhuzeIW_H-Dyncdrc3w0f2WxdH3oRcnvPTwrb" .
    # issuer3
    <did:example:issuer3> <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> .
    <did:example:issuer3#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
    <did:example:issuer3#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer3> .
    <did:example:issuer3#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "uH1yGFG6C1pJd_N45wkOPrSNdvILdLm0c_0AXXRDGZy8" .
    <did:example:issuer3#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "uidSE_Urr5MFE4SoqV3TZTBHPHM-tkpdRhBPrYeIbsudglVV_cddyEstHJOmSkfPOFsvEuA9qtWjFNpBebVSS4DPxBfNNWESSCz_vrnH62hbfpWdJSFR8YbqjborvpgM6" .
    "#;

    #[test]
    fn request_blind_sign_success() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let secret = b"SECRET";
        let challenge = "challenge";
        let request = request_blind_sign(&mut rng, secret, Some(challenge), None).unwrap();
        let verified = verify_blind_sign_request(
            &mut rng,
            &request.commitment,
            request.pok_for_commitment.unwrap(),
            Some(challenge),
        );
        assert!(verified.is_ok())
    }

    #[test]
    fn request_blind_sign_string_success() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let secret = b"SECRET";
        let challenge = "challenge";
        let request = request_blind_sign_string(&mut rng, secret, Some(challenge), None).unwrap();
        let verified = verify_blind_sign_request_string(
            &mut rng,
            &request.commitment,
            &request.pok_for_commitment.unwrap(),
            Some(challenge),
        );
        assert!(verified.is_ok());
    }

    const VC_1: &str = r#"
    <did:example:john> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
    <did:example:john> <http://schema.org/name> "John Smith" .
    <did:example:john> <http://example.org/vocab/isPatientOf> _:b0 .
    <did:example:john> <http://schema.org/worksFor> _:b1 .
    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
    _:b0 <http://example.org/vocab/lotNumber> "0000001" .
    _:b0 <http://example.org/vocab/vaccinationDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:b0 <http://example.org/vocab/vaccine> <http://example.org/vaccine/a> .
    _:b0 <http://example.org/vocab/vaccine> <http://example.org/vaccine/b> .
    _:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Organization> .
    _:b1 <http://schema.org/name> "ABC inc." .
    <http://example.org/vcred/00> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
    <http://example.org/vcred/00> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:john> .
    <http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
    <http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    <http://example.org/vcred/00> <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    "#;
    const VC_PROOF_WITHOUT_PROOFVALUE_1: &str = r#"
    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
    _:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
    _:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
    "#;
    const VC_PROOF_WITHOUT_PROOFVALUE_AND_DATETIME_1: &str = r#"
    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
    _:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
    _:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
    "#;
    const VC_PROOF_WITHOUT_PROOFVALUE_1_WITH_CRYPTOSUITE: &str = r#"
    _:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-bound-signature-2023" . # valid cryptosuite
    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
    _:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
    _:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
    "#;
    const VC_PROOF_WITHOUT_PROOFVALUE_1_WITH_INVALID_CRYPTOSUITE: &str = r#"
    _:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" . # invalid cryptosuite
    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
    _:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
    _:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
    "#;

    #[test]
    fn blind_sign_success() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let secret = b"SECRET";
        let challenge = "challenge";
        let request = request_blind_sign(&mut rng, secret, Some(challenge), None).unwrap();

        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();
        let unsecured_document = get_graph_from_ntriples(VC_1).unwrap();
        let proof_config = get_graph_from_ntriples(VC_PROOF_WITHOUT_PROOFVALUE_1).unwrap();
        let mut vc = VerifiableCredential::new(unsecured_document, proof_config);
        let result = blind_sign(&mut rng, &request.commitment, &mut vc, &key_graph);
        assert!(result.is_ok());
    }

    #[test]
    fn blind_sign_without_datetime_success() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let secret = b"SECRET";
        let challenge = "challenge";
        let request = request_blind_sign(&mut rng, secret, Some(challenge), None).unwrap();

        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();
        let unsecured_document = get_graph_from_ntriples(VC_1).unwrap();
        let proof_config =
            get_graph_from_ntriples(VC_PROOF_WITHOUT_PROOFVALUE_AND_DATETIME_1).unwrap();
        let mut vc = VerifiableCredential::new(unsecured_document, proof_config);
        let result = blind_sign(&mut rng, &request.commitment, &mut vc, &key_graph);
        assert!(result.is_ok());
    }

    #[test]
    fn blind_sign_with_cryptosuite_success() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let secret = b"SECRET";
        let challenge = "challenge";
        let request = request_blind_sign(&mut rng, secret, Some(challenge), None).unwrap();

        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();
        let unsecured_document = get_graph_from_ntriples(VC_1).unwrap();
        let proof_config =
            get_graph_from_ntriples(VC_PROOF_WITHOUT_PROOFVALUE_1_WITH_CRYPTOSUITE).unwrap();
        let mut vc = VerifiableCredential::new(unsecured_document, proof_config);
        let result = blind_sign(&mut rng, &request.commitment, &mut vc, &key_graph);
        assert!(result.is_ok())
    }

    #[test]
    fn blind_sign_with_invalid_cryptosuite_failure() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let secret = b"SECRET";
        let challenge = "challenge";
        let request = request_blind_sign(&mut rng, secret, Some(challenge), None).unwrap();

        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();
        let unsecured_document = get_graph_from_ntriples(VC_1).unwrap();
        let proof_config =
            get_graph_from_ntriples(VC_PROOF_WITHOUT_PROOFVALUE_1_WITH_INVALID_CRYPTOSUITE)
                .unwrap();
        let mut vc = VerifiableCredential::new(unsecured_document, proof_config);
        let result = blind_sign(&mut rng, &request.commitment, &mut vc, &key_graph);
        assert!(matches!(
            result,
            Err(RDFProofsError::InvalidProofConfiguration)
        ))
    }

    #[test]
    fn blind_sign_string_success() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let secret = b"SECRET";
        let challenge = "challenge";
        let request = request_blind_sign_string(&mut rng, secret, Some(challenge), None).unwrap();

        let result = blind_sign_string(
            &mut rng,
            &request.commitment,
            VC_1,
            VC_PROOF_WITHOUT_PROOFVALUE_1,
            KEY_GRAPH,
        );
        assert!(result.is_ok())
    }

    #[test]
    fn blind_sign_and_unblind_success() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let secret = b"SECRET";
        let challenge = "challenge";
        let request = request_blind_sign(&mut rng, secret, Some(challenge), None).unwrap();

        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();
        let unsecured_document = get_graph_from_ntriples(VC_1).unwrap();
        let proof_config = get_graph_from_ntriples(VC_PROOF_WITHOUT_PROOFVALUE_1).unwrap();
        let mut vc = VerifiableCredential::new(unsecured_document, proof_config);
        blind_sign(&mut rng, &request.commitment, &mut vc, &key_graph).unwrap();

        let result = unblind(&mut vc, &request.blinding);
        assert!(result.is_ok());
        assert_eq!(vc.proof.triples_for_predicate(PROOF_VALUE).count(), 1)
    }

    #[test]
    fn blind_sign_and_unblind_string_success() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let secret = b"SECRET";
        let challenge = "challenge";
        let request = request_blind_sign_string(&mut rng, secret, Some(challenge), None).unwrap();

        let proof = blind_sign_string(
            &mut rng,
            &request.commitment,
            VC_1,
            VC_PROOF_WITHOUT_PROOFVALUE_1,
            KEY_GRAPH,
        )
        .unwrap();

        let result = unblind_string(VC_1, &proof, &request.blinding);
        assert!(result.is_ok());
    }

    #[test]
    fn blind_sign_and_unblind_and_verify_success() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let secret = b"SECRET";
        let challenge = "challenge";
        let request = request_blind_sign(&mut rng, secret, Some(challenge), None).unwrap();

        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();
        let unsecured_document = get_graph_from_ntriples(VC_1).unwrap();
        let proof_config = get_graph_from_ntriples(VC_PROOF_WITHOUT_PROOFVALUE_1).unwrap();
        let mut vc = VerifiableCredential::new(unsecured_document, proof_config);
        blind_sign(&mut rng, &request.commitment, &mut vc, &key_graph).unwrap();

        unblind(&mut vc, &request.blinding).unwrap();

        let result = blind_verify(secret, &vc, &key_graph);
        assert!(result.is_ok());
    }

    #[test]
    fn blind_sign_and_unblind_and_verify_string_success() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let secret = b"SECRET";
        let challenge = "challenge";
        let request = request_blind_sign_string(&mut rng, secret, Some(challenge), None).unwrap();

        let blinded_proof = blind_sign_string(
            &mut rng,
            &request.commitment,
            VC_1,
            VC_PROOF_WITHOUT_PROOFVALUE_1,
            KEY_GRAPH,
        )
        .unwrap();

        let proof = unblind_string(VC_1, &blinded_proof, &request.blinding).unwrap();

        let result = blind_verify_string(secret, VC_1, &proof, KEY_GRAPH);
        assert!(result.is_ok(), "{:?}", result);
    }

    #[test]
    fn blind_sign_and_unblind_and_verify_with_invalid_secret_failure() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let secret = b"SECRET";
        let challenge = "challenge";
        let request = request_blind_sign(&mut rng, secret, Some(challenge), None).unwrap();

        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();
        let unsecured_document = get_graph_from_ntriples(VC_1).unwrap();
        let proof_config = get_graph_from_ntriples(VC_PROOF_WITHOUT_PROOFVALUE_1).unwrap();
        let mut vc = VerifiableCredential::new(unsecured_document, proof_config);
        blind_sign(&mut rng, &request.commitment, &mut vc, &key_graph).unwrap();

        unblind(&mut vc, &request.blinding).unwrap();

        // verify with invalid secret
        let secret = b"INVALID";
        let result = blind_verify(secret, &vc, &key_graph);
        assert!(matches!(
            result,
            Err(RDFProofsError::BBSPlus(
                bbs_plus::prelude::BBSPlusError::InvalidSignature
            ))
        ))
    }
}
