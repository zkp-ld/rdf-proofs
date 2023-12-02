use crate::{
    common::{
        ark_to_base64url, canonicalize_graph_into_terms, configure_proof_core, get_delimiter,
        get_graph_from_ntriples, get_hasher, get_vc_from_ntriples,
        get_verification_method_identifier, hash_byte_to_field, hash_terms_to_field,
        multibase_to_ark, BBSPlusSignature, Fr,
    },
    constants::{CRYPTOSUITE_BOUND_SIGN, CRYPTOSUITE_SIGN},
    context::{DATA_INTEGRITY_PROOF, MULTIBASE, PROOF_VALUE},
    error::RDFProofsError,
    key_gen::generate_params,
    key_graph::KeyGraph,
    vc::VerifiableCredential,
};
use ark_std::rand::RngCore;
use oxrdf::{vocab::rdf::TYPE, Graph, LiteralRef, Term, TripleRef};

pub fn sign<R: RngCore>(
    rng: &mut R,
    unsecured_credential: &mut VerifiableCredential,
    key_graph: &KeyGraph,
    shared_secret: Option<&[u8]>,
) -> Result<(), RDFProofsError> {
    let proof = sign_core(rng, unsecured_credential, key_graph, shared_secret)?;
    unsecured_credential.proof = proof;
    Ok(())
}

pub fn sign_string<R: RngCore>(
    rng: &mut R,
    document: &str,
    proof_options: &str,
    key_graph: &str,
    shared_secret: Option<&[u8]>,
) -> Result<String, RDFProofsError> {
    let unsecured_credential = get_vc_from_ntriples(document, proof_options)?;
    let key_graph = get_graph_from_ntriples(key_graph)?.into();
    let proof = sign_core(rng, &unsecured_credential, &key_graph, shared_secret)?;
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
    shared_secret: Option<&[u8]>,
) -> Result<Graph, RDFProofsError> {
    let VerifiableCredential {
        document,
        proof: proof_option,
    } = unsecured_credential;
    let transformed_data = transform(document)?;
    let proof_config = match shared_secret {
        Some(_secret) => configure_proof_for_bound(&proof_option)?,
        None => configure_proof(&proof_option)?,
    };
    let canonical_proof_config = transform(&proof_config)?;
    let hash_data = hash(shared_secret, &transformed_data, &canonical_proof_config)?;
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

fn configure_proof_for_bound(proof_options: &Graph) -> Result<Graph, RDFProofsError> {
    configure_proof_core(proof_options, CRYPTOSUITE_BOUND_SIGN)
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
    let signature_base64url = ark_to_base64url(&signature)?;

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
    let signature: BBSPlusSignature = multibase_to_ark(proof_value)?;
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

#[cfg(test)]
mod tests {
    use crate::{
        blind_verify,
        common::{get_graph_from_ntriples, multibase_to_ark, BBSPlusSignature},
        context::PROOF_VALUE,
        error::RDFProofsError,
        sign, sign_string, verify, verify_string, KeyGraph, VerifiableCredential,
    };
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use oxrdf::TermRef;

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
    _:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" . # valid cryptosuite
    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
    _:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
    _:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
    "#;
    const VC_PROOF_WITHOUT_PROOFVALUE_1_WITH_INVALID_CRYPTOSUITE: &str = r#"
    _:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-blind-signature-2023" . # invalid cryptosuite
    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
    _:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
    _:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
    "#;
    const VC_PROOF_1: &str = r#"
    _:b0 <https://w3id.org/security#proofValue> "ui_TYLyZXnF1LRhdzEDrKiAWA0Tbrm1GmCHXBVnX39BTBnIbdFLc9p2jRAw0H4jzznHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
    _:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
    _:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
    _:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
    "#;
    const VC_1_MODIFIED: &str = r#"
    <did:example:john> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
    <did:example:john> <http://schema.org/name> "**********************************" .  # modified
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
    const VC_PROOF_1_MODIFIED: &str = r#"
    _:b0 <https://w3id.org/security#proofValue> "ui_TYLyZXnF1LRhdzEDrKiAWA0Tbrm1GmCHXBVnX39BTBnIbdFLc9p2jRAw0H4jzznHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
    _:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
    _:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
    _:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer1#bls12_381-g2-pub001> . # the other issuer's pk
    "#;
    const _VC_2: &str = r#"
    <http://example.org/vaccine/a> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccine> .
    <http://example.org/vaccine/a> <http://schema.org/name> "AwesomeVaccine" .
    <http://example.org/vaccine/a> <http://schema.org/manufacturer> <http://example.org/awesomeCompany> .
    <http://example.org/vaccine/a> <http://schema.org/status> "active" .
    <http://example.org/vicred/a> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
    <http://example.org/vicred/a> <https://www.w3.org/2018/credentials#credentialSubject> <http://example.org/vaccine/a> .
    <http://example.org/vicred/a> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer3> .
    <http://example.org/vicred/a> <https://www.w3.org/2018/credentials#issuanceDate> "2020-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    <http://example.org/vicred/a> <https://www.w3.org/2018/credentials#expirationDate> "2023-12-31T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    "#;
    const _VC_PROOF_WITHOUT_PROOFVALUE_2: &str = r#"
    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
    _:b0 <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
    _:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> .
    "#;

    fn print_signature(vc: &VerifiableCredential) {
        let proof_value_triple = vc.proof.triples_for_predicate(PROOF_VALUE).next().unwrap();
        if let TermRef::Literal(v) = proof_value_triple.object {
            let proof_value = v.value();
            let signature: BBSPlusSignature = multibase_to_ark(proof_value).unwrap();
            println!("decoded signature:\n{:#?}\n", signature);
        }
    }

    #[test]
    fn sign_and_verify_success() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();
        let unsecured_document = get_graph_from_ntriples(VC_1).unwrap();
        let proof_config = get_graph_from_ntriples(VC_PROOF_WITHOUT_PROOFVALUE_1).unwrap();
        let mut vc = VerifiableCredential::new(unsecured_document, proof_config);
        sign(&mut rng, &mut vc, &key_graph, None).unwrap();
        println!("vc: {}", vc);
        print_signature(&vc);
        assert!(verify(&vc, &key_graph).is_ok())
    }

    #[test]
    fn sign_with_shared_secret_and_blind_verify() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();
        let unsecured_document = get_graph_from_ntriples(VC_1).unwrap();
        let proof_config = get_graph_from_ntriples(VC_PROOF_WITHOUT_PROOFVALUE_1).unwrap();
        let mut vc = VerifiableCredential::new(unsecured_document, proof_config);
        let secret = b"SECRET";
        sign(&mut rng, &mut vc, &key_graph, Some(secret)).unwrap();
        println!("vc: {}", vc);
        print_signature(&vc);
        assert!(blind_verify(secret, &vc, &key_graph).is_ok())
    }

    #[test]
    fn sign_and_verify_without_created_datetime_success() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();
        let unsecured_document = get_graph_from_ntriples(VC_1).unwrap();
        let proof_config =
            get_graph_from_ntriples(VC_PROOF_WITHOUT_PROOFVALUE_AND_DATETIME_1).unwrap();
        let mut vc = VerifiableCredential::new(unsecured_document, proof_config);
        sign(&mut rng, &mut vc, &key_graph, None).unwrap();
        println!("vc: {}", vc);
        print_signature(&vc);
        assert!(verify(&vc, &key_graph).is_ok())
    }

    #[test]
    fn sign_and_verify_with_cryptosuite_success() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();
        let unsecured_document = get_graph_from_ntriples(VC_1).unwrap();
        let proof_config =
            get_graph_from_ntriples(VC_PROOF_WITHOUT_PROOFVALUE_1_WITH_CRYPTOSUITE).unwrap();
        let mut vc = VerifiableCredential::new(unsecured_document, proof_config);
        sign(&mut rng, &mut vc, &key_graph, None).unwrap();
        assert!(verify(&vc, &key_graph).is_ok())
    }

    #[test]
    fn sign_and_verify_with_invalid_cryptosuite_failure() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();
        let unsecured_document = get_graph_from_ntriples(VC_1).unwrap();
        let proof_config =
            get_graph_from_ntriples(VC_PROOF_WITHOUT_PROOFVALUE_1_WITH_INVALID_CRYPTOSUITE)
                .unwrap();
        let mut vc = VerifiableCredential::new(unsecured_document, proof_config);
        let result = sign(&mut rng, &mut vc, &key_graph, None);
        assert!(result.is_err())
    }

    #[test]
    fn sign_and_verify_string_success() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let proof = sign_string(
            &mut rng,
            VC_1,
            VC_PROOF_WITHOUT_PROOFVALUE_1,
            KEY_GRAPH,
            None,
        )
        .unwrap();
        assert!(verify_string(VC_1, &proof, KEY_GRAPH).is_ok())
    }

    #[test]
    fn verify_success() {
        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();
        let unsecured_document = get_graph_from_ntriples(VC_1).unwrap();
        let signed_proof_config = get_graph_from_ntriples(VC_PROOF_1).unwrap();
        let vc = VerifiableCredential::new(unsecured_document, signed_proof_config);
        let verified = verify(&vc, &key_graph);
        assert!(verified.is_ok(), "{:?}", verified)
    }

    #[test]
    fn verify_string_success() {
        assert!(verify_string(VC_1, VC_PROOF_1, KEY_GRAPH).is_ok())
    }

    #[test]
    fn verify_failed_modified_document() {
        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();
        let unsecured_document = get_graph_from_ntriples(VC_1_MODIFIED).unwrap();
        let signed_proof_config = get_graph_from_ntriples(VC_PROOF_1).unwrap();
        let vc = VerifiableCredential::new(unsecured_document, signed_proof_config);
        let verified = verify(&vc, &key_graph);
        assert!(matches!(
            verified,
            Err(RDFProofsError::BBSPlus(
                bbs_plus::prelude::BBSPlusError::InvalidSignature
            ))
        ))
    }

    #[test]
    fn verify_string_failed_modified_document() {
        let verified = verify_string(VC_1_MODIFIED, VC_PROOF_1, KEY_GRAPH);
        assert!(matches!(
            verified,
            Err(RDFProofsError::BBSPlus(
                bbs_plus::prelude::BBSPlusError::InvalidSignature
            ))
        ))
    }

    #[test]
    fn verify_failed_invalid_pk() {
        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();
        let unsecured_document = get_graph_from_ntriples(VC_1).unwrap();
        let signed_proof_config = get_graph_from_ntriples(VC_PROOF_1_MODIFIED).unwrap();
        let vc = VerifiableCredential::new(unsecured_document, signed_proof_config);
        let verified = verify(&vc, &key_graph);
        assert!(matches!(
            verified,
            Err(RDFProofsError::BBSPlus(
                bbs_plus::error::BBSPlusError::InvalidSignature
            ))
        ))
    }

    #[test]
    fn verify_string_failed_invalid_pk() {
        let verified = verify_string(VC_1, VC_PROOF_1_MODIFIED, KEY_GRAPH);
        assert!(matches!(
            verified,
            Err(RDFProofsError::BBSPlus(
                bbs_plus::prelude::BBSPlusError::InvalidSignature
            ))
        ))
    }
}
