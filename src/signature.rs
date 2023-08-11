use crate::{
    common::{
        get_delimiter, get_hasher, get_verification_method_identifier, hash_terms_to_field, Fr,
    },
    constants::CRYPTOSUITE_SIGN,
    context::{CREATED, CRYPTOSUITE, DATA_INTEGRITY_PROOF, PROOF_VALUE},
    error::RDFProofsError,
    keygen::generate_params,
    loader::DocumentLoader,
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
use rdf_canon::{issue_graph, relabel_graph, sort_graph};
use std::str::FromStr;

pub fn sign<R: RngCore>(
    rng: &mut R,
    unsecured_credential: &mut VerifiableCredential,
    document_loader: &DocumentLoader,
) -> Result<(), RDFProofsError> {
    let VerifiableCredential { document, proof } = unsecured_credential;
    let transformed_data = transform(document, proof)?;
    let canonical_proof_config = configure_proof(proof)?;
    let hash_data = hash(&transformed_data, &canonical_proof_config)?;
    let proof_value = serialize_proof(rng, &hash_data, proof, document_loader)?;
    add_proof_value(unsecured_credential, proof_value)?;
    Ok(())
}

pub fn verify(
    secured_credential: &VerifiableCredential,
    document_loader: &DocumentLoader,
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
    verify_base_proof(hash_data, proof_value, &proof_config, document_loader)
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
    let issued_identifiers_map = &issue_graph(graph)?;
    let canonicalized_graph = relabel_graph(graph, issued_identifiers_map)?;
    let canonicalized_triples = sort_graph(&canonicalized_graph);
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
    document_loader: &DocumentLoader,
) -> Result<String, RDFProofsError> {
    let message_count = hash_data.len();

    let verification_method_identifier = get_verification_method_identifier(proof_options)?;
    let (secret_key, _public_key) = document_loader.get_keypair(verification_method_identifier)?;

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
        Literal::new_simple_literal(proof_value),
    ));
    Ok(())
}

fn verify_base_proof(
    hash_data: Vec<Fr>,
    proof_value: &str,
    proof_config: &Graph,
    document_loader: &DocumentLoader,
) -> Result<(), RDFProofsError> {
    let (_, proof_value_bytes) = multibase::decode(proof_value)?;
    let signature = BBSSignatureG1::<Bls12_381>::deserialize_compressed(&*proof_value_bytes)?;
    let verification_method_identifier = get_verification_method_identifier(proof_config)?;
    let pk = document_loader.get_public_key(verification_method_identifier)?;
    let params = generate_params(hash_data.len());
    Ok(signature.verify(&hash_data, pk, params)?)
}

#[cfg(test)]
mod tests {
    use crate::{
        error::RDFProofsError,
        loader::DocumentLoader,
        signature::{sign, verify},
        tests::{get_graph_from_ntriples_str, print_signature, print_vc, DOCUMENT_LOADER_NTRIPLES},
        vc::VerifiableCredential,
    };
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use bbs_plus::prelude::BBSPlusError::InvalidSignature;

    #[test]
    fn sign_and_verify_success() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed

        let unsecured_document_ntriples = r#"
<did:example:john> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
<did:example:john> <http://schema.org/name> "John Smith" .
<did:example:john> <http://example.org/vocab/isPatientOf> _:a91b3e .
_:a91b3e <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
_:a91b3e <http://example.org/vocab/lotNumber> "0000001" .
_:a91b3e <http://example.org/vocab/vaccinationDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:a91b3e <http://example.org/vocab/vaccine> <http://example.org/vaccine/a> .
_:a91b3e <http://example.org/vocab/vaccine> <http://example.org/vaccine/b> .
<http://example.org/vcred/00> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:john> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
"#;
        let proof_config_ntriples = r#"
_:6b92db <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:6b92db <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:6b92db <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:6b92db <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:6b92db <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
"#;
        let document_loader: DocumentLoader =
            get_graph_from_ntriples_str(DOCUMENT_LOADER_NTRIPLES).into();
        let unsecured_document = get_graph_from_ntriples_str(unsecured_document_ntriples);
        let proof_config = get_graph_from_ntriples_str(proof_config_ntriples);
        let mut vc = VerifiableCredential::new(unsecured_document, proof_config);
        sign(&mut rng, &mut vc, &document_loader).unwrap();
        print_vc(&vc);
        print_signature(&vc);
        assert!(verify(&vc, &document_loader).is_ok())
    }

    #[test]
    fn sign_and_verify_success_issuer1() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed

        let unsecured_document_ntriples = r#"
<did:example:john> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
<did:example:john> <http://schema.org/name> "John Smith" .
<did:example:john> <http://example.org/vocab/isPatientOf> _:a91b3e .
_:a91b3e <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
_:a91b3e <http://example.org/vocab/lotNumber> "0000001" .
_:a91b3e <http://example.org/vocab/vaccinationDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:a91b3e <http://example.org/vocab/vaccine> <http://example.org/vaccine/a> .
_:a91b3e <http://example.org/vocab/vaccine> <http://example.org/vaccine/b> .
<http://example.org/vcred/00> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:john> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer1> .  # issuer1
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
"#;
        let proof_config_ntriples = r#"
_:6b92db <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:6b92db <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:6b92db <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:6b92db <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:6b92db <https://w3id.org/security#verificationMethod> <did:example:issuer1#bls12_381-g2-pub001> .  # issuer1
"#;
        let document_loader: DocumentLoader =
            get_graph_from_ntriples_str(DOCUMENT_LOADER_NTRIPLES).into();
        let unsecured_document = get_graph_from_ntriples_str(unsecured_document_ntriples);
        let proof_config = get_graph_from_ntriples_str(proof_config_ntriples);
        let mut vc = VerifiableCredential::new(unsecured_document, proof_config);
        sign(&mut rng, &mut vc, &document_loader).unwrap();
        print_vc(&vc);
        print_signature(&vc);
        assert!(verify(&vc, &document_loader).is_ok())
    }

    #[test]
    fn sign_and_verify_success_issuer3() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed

        let unsecured_document_ntriples = r#"
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
        let proof_config_ntriples = r#"
_:wTnTxH <https://w3id.org/security#proofValue>"upqbT4ZPXjIRFKEQt5k-Bs5g_KG50zREjSMFH0wL5wkDAs7Ci2Qg58_EJLDffc2M0nHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ" .
_:wTnTxH <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:wTnTxH <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:wTnTxH <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:wTnTxH <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:wTnTxH <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> .
"#;
        let document_loader: DocumentLoader =
            get_graph_from_ntriples_str(DOCUMENT_LOADER_NTRIPLES).into();
        let unsecured_document = get_graph_from_ntriples_str(unsecured_document_ntriples);
        let proof_config = get_graph_from_ntriples_str(proof_config_ntriples);
        let mut vc = VerifiableCredential::new(unsecured_document, proof_config);
        sign(&mut rng, &mut vc, &document_loader).unwrap();
        print_vc(&vc);
        print_signature(&vc);
        assert!(verify(&vc, &document_loader).is_ok())
    }

    #[test]
    fn verify_success() {
        let unsecured_document_ntriples = r#"
<did:example:john> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
<did:example:john> <http://schema.org/name> "John Smith" .
<did:example:john> <http://example.org/vocab/isPatientOf> _:a91b3e .
_:a91b3e <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
_:a91b3e <http://example.org/vocab/lotNumber> "0000001" .
_:a91b3e <http://example.org/vocab/vaccinationDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:a91b3e <http://example.org/vocab/vaccine> <http://example.org/vaccine/a> .
_:a91b3e <http://example.org/vocab/vaccine> <http://example.org/vaccine/b> .
<http://example.org/vcred/00> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:john> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
"#;
        let signed_proof_config_ntriples = r#"
_:6b92db <https://w3id.org/security#proofValue> "ugZveToWB9bUAm3RDFWeORovPDYdIgNWbsquhn334R78TCG86fad_3JiA6yh_f-bsnHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ" .
_:6b92db <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:6b92db <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:6b92db <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:6b92db <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:6b92db <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
"#;
        let document_loader: DocumentLoader =
            get_graph_from_ntriples_str(DOCUMENT_LOADER_NTRIPLES).into();
        let unsecured_document = get_graph_from_ntriples_str(unsecured_document_ntriples);
        let signed_proof_config = get_graph_from_ntriples_str(signed_proof_config_ntriples);
        let vc = VerifiableCredential::new(unsecured_document, signed_proof_config);
        let verified = verify(&vc, &document_loader);
        assert!(verified.is_ok())
    }

    #[test]
    fn verify_success_issuer1() {
        let unsecured_document_ntriples = r#"
<did:example:john> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
<did:example:john> <http://schema.org/name> "John Smith" .
<did:example:john> <http://example.org/vocab/isPatientOf> _:a91b3e .
_:a91b3e <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
_:a91b3e <http://example.org/vocab/lotNumber> "0000001" .
_:a91b3e <http://example.org/vocab/vaccinationDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:a91b3e <http://example.org/vocab/vaccine> <http://example.org/vaccine/a> .
_:a91b3e <http://example.org/vocab/vaccine> <http://example.org/vaccine/b> .
<http://example.org/vcred/00> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:john> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer1> .  # issuer1
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
"#;
        let signed_proof_config_ntriples = r#"
_:6b92db <https://w3id.org/security#proofValue> "ups_0MAlFoDctUdvWimqsLAPHdPQb55qIjiktM3H7t_WOTitkXzyiOpdFw67bWjhTnHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ" .
_:6b92db <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:6b92db <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:6b92db <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:6b92db <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:6b92db <https://w3id.org/security#verificationMethod> <did:example:issuer1#bls12_381-g2-pub001> .  # issuer1
"#;
        let document_loader: DocumentLoader =
            get_graph_from_ntriples_str(DOCUMENT_LOADER_NTRIPLES).into();
        let unsecured_document = get_graph_from_ntriples_str(unsecured_document_ntriples);
        let signed_proof_config = get_graph_from_ntriples_str(signed_proof_config_ntriples);
        let vc = VerifiableCredential::new(unsecured_document, signed_proof_config);
        let verified = verify(&vc, &document_loader);
        assert!(verified.is_ok())
    }

    #[test]
    fn verify_failed_modified_document() {
        let unsecured_document_ntriples = r#"
<did:example:john> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
<did:example:john> <http://schema.org/name> "**********************************" .  # modified
<did:example:john> <http://example.org/vocab/isPatientOf> _:a91b3e .
_:a91b3e <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
_:a91b3e <http://example.org/vocab/lotNumber> "0000001" .
_:a91b3e <http://example.org/vocab/vaccinationDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:a91b3e <http://example.org/vocab/vaccine> <http://example.org/vaccine/a> .
_:a91b3e <http://example.org/vocab/vaccine> <http://example.org/vaccine/b> .
<http://example.org/vcred/00> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:john> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
"#;
        let signed_proof_config_ntriples = r#"
_:6b92db <https://w3id.org/security#proofValue> "ugZveToWB9bUAm3RDFWeORovPDYdIgNWbsquhn334R78TCG86fad_3JiA6yh_f-bsnHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ" .
_:6b92db <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:6b92db <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:6b92db <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:6b92db <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:6b92db <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
"#;
        let document_loader: DocumentLoader =
            get_graph_from_ntriples_str(DOCUMENT_LOADER_NTRIPLES).into();
        let unsecured_document = get_graph_from_ntriples_str(unsecured_document_ntriples);
        let signed_proof_config = get_graph_from_ntriples_str(signed_proof_config_ntriples);
        let vc = VerifiableCredential::new(unsecured_document, signed_proof_config);
        let verified = verify(&vc, &document_loader);
        assert!(matches!(
            verified,
            Err(RDFProofsError::BBSPlus(InvalidSignature))
        ))
    }

    #[test]
    fn verify_failed_invalid_pk() {
        let unsecured_document_ntriples = r#"
<did:example:john> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
<did:example:john> <http://schema.org/name> "John Smith" .
<did:example:john> <http://example.org/vocab/isPatientOf> _:a91b3e .
_:a91b3e <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
_:a91b3e <http://example.org/vocab/lotNumber> "0000001" .
_:a91b3e <http://example.org/vocab/vaccinationDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:a91b3e <http://example.org/vocab/vaccine> <http://example.org/vaccine/a> .
_:a91b3e <http://example.org/vocab/vaccine> <http://example.org/vaccine/b> .
<http://example.org/vcred/00> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:john> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
"#;
        let signed_proof_config_ntriples = r#"
_:6b92db <https://w3id.org/security#proofValue> "ugZveToWB9bUAm3RDFWeORovPDYdIgNWbsquhn334R78TCG86fad_3JiA6yh_f-bsnHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ" .
_:6b92db <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:6b92db <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:6b92db <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:6b92db <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:6b92db <https://w3id.org/security#verificationMethod> <did:example:issuer1#bls12_381-g2-pub001> . # the other issuer's pk
"#;
        let document_loader: DocumentLoader =
            get_graph_from_ntriples_str(DOCUMENT_LOADER_NTRIPLES).into();
        let unsecured_document = get_graph_from_ntriples_str(unsecured_document_ntriples);
        let signed_proof_config = get_graph_from_ntriples_str(signed_proof_config_ntriples);
        let vc = VerifiableCredential::new(unsecured_document, signed_proof_config);
        let verified = verify(&vc, &document_loader);
        assert!(matches!(
            verified,
            Err(RDFProofsError::BBSPlus(InvalidSignature))
        ))
    }
}
