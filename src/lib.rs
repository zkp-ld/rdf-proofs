mod blind_signature;
mod common;
mod constants;
pub mod context;
mod derive_proof;
pub mod error;
pub mod key_gen;
mod key_graph;
mod ordered_triple;
mod signature;
mod vc;
mod verify_proof;

pub use blind_signature::{
    blind_sign, blind_sign_request, blind_sign_request_string, blind_sign_string, blind_verify,
    unblind, unblind_string,
};
pub use derive_proof::{derive_proof, derive_proof_string};
pub use key_graph::KeyGraph;
pub use signature::{sign, sign_string, verify, verify_string};
pub use vc::{VcPair, VcPairString, VerifiableCredential};
pub use verify_proof::{verify_proof, verify_proof_string};

#[cfg(test)]
mod tests {
    use crate::{
        common::{get_dataset_from_nquads, get_graph_from_ntriples, BBSPlusSignature},
        context::PROOF_VALUE,
        derive_proof,
        derive_proof::get_deanon_map_from_string,
        derive_proof_string,
        error::RDFProofsError,
        key_gen::{generate_keypair, generate_params},
        sign, sign_string, verify, verify_proof, verify_proof_string, verify_string, KeyGraph,
        VcPair, VcPairString, VerifiableCredential,
    };
    use ark_serialize::CanonicalDeserialize;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use oxrdf::{NamedOrBlankNode, Term, TermRef};
    use std::collections::HashMap;

    pub(crate) const KEY_GRAPH: &str = r#"
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

    pub(crate) fn print_signature(vc: &VerifiableCredential) {
        let proof_value_triple = vc.proof.triples_for_predicate(PROOF_VALUE).next().unwrap();
        if let TermRef::Literal(v) = proof_value_triple.object {
            let proof_value = v.value();
            let (_, proof_value_bytes) = multibase::decode(proof_value).unwrap();
            let signature = BBSPlusSignature::deserialize_compressed(&*proof_value_bytes).unwrap();
            println!("decoded signature:\n{:#?}\n", signature);
        }
    }

    // tests for parameter and key generation
    #[test]
    fn params_gen_success() {
        let params1 = generate_params(1);
        let params2 = generate_params(2);
        let params3 = generate_params(3);
        println!("{:#?}", params1);
        println!("{:#?}", params2);
        println!("{:#?}", params3);
    }

    #[test]
    fn key_gen_success() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let keypair1 = generate_keypair(&mut rng);
        let keypair2 = generate_keypair(&mut rng);
        let keypair3 = generate_keypair(&mut rng);
        assert!(keypair1.is_ok());
        assert!(keypair2.is_ok());
        assert!(keypair3.is_ok());
    }

    // tests for sign & verify

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
    _:b0 <https://w3id.org/security#proofValue> "ulyXJi_kpGXb2nUqVCRTzw03zFZyswkPLszC47yoRvUbGSkw2-v6GnY7X31hRYt4AnHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
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
    _:b0 <https://w3id.org/security#proofValue> "ulyXJi_kpGXb2nUqVCRTzw03zFZyswkPLszC47yoRvUbGSkw2-v6GnY7X31hRYt4AnHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
    _:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
    _:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
    _:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer1#bls12_381-g2-pub001> . # the other issuer's pk
    "#;

    #[test]
    fn sign_and_verify_success() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();
        let unsecured_document = get_graph_from_ntriples(VC_1).unwrap();
        let proof_config = get_graph_from_ntriples(VC_PROOF_WITHOUT_PROOFVALUE_1).unwrap();
        let mut vc = VerifiableCredential::new(unsecured_document, proof_config);
        sign(&mut rng, &mut vc, &key_graph).unwrap();
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
        sign(&mut rng, &mut vc, &key_graph).unwrap();
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
        let result = sign(&mut rng, &mut vc, &key_graph);
        assert!(result.is_err())
    }

    #[test]
    fn sign_and_verify_string_success() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let proof = sign_string(&mut rng, VC_1, VC_PROOF_WITHOUT_PROOFVALUE_1, KEY_GRAPH).unwrap();
        assert!(verify_string(VC_1, &proof, KEY_GRAPH).is_ok())
    }

    #[test]
    fn verify_success() {
        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();
        let unsecured_document = get_graph_from_ntriples(VC_1).unwrap();
        let signed_proof_config = get_graph_from_ntriples(VC_PROOF_1).unwrap();
        let vc = VerifiableCredential::new(unsecured_document, signed_proof_config);
        let verified = verify(&vc, &key_graph);
        assert!(verified.is_ok())
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

    // tests for derive_proof & verify_proof

    const VC_2: &str = r#"
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
    const VC_PROOF_2: &str = r#"
    _:b0 <https://w3id.org/security#proofValue> "uh-n1eUTNbs6fG9NMTPTL98zwcwfA1N4GCm0XXl__t5tMKOKU1LBfwt1f7Dtoy9dHnHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
    _:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
    _:b0 <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
    _:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> .
    "#;
    const DISCLOSED_VC_1: &str = r#"
    _:e0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
    _:e0 <http://example.org/vocab/isPatientOf> _:b0 .
    _:e0 <http://schema.org/worksFor> _:b1 .
    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
    _:b0 <http://example.org/vocab/vaccine> _:e1 .
    _:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Organization> .
    _:e2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
    _:e2 <https://www.w3.org/2018/credentials#credentialSubject> _:e0 .
    _:e2 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
    _:e2 <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:e2 <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    "#;
    const DISCLOSED_VC_PROOF_1: &str = r#"
    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
    _:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
    _:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
    _:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
    "#;
    const DISCLOSED_VC_2: &str = r#"
    _:e1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccine> .
    _:e1 <http://schema.org/status> "active" .
    _:e3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
    _:e3 <https://www.w3.org/2018/credentials#credentialSubject> _:e1 .
    _:e3 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer3> .
    _:e3 <https://www.w3.org/2018/credentials#issuanceDate> "2020-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:e3 <https://www.w3.org/2018/credentials#expirationDate> "2023-12-31T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    "#;
    const DISCLOSED_VC_PROOF_2: &str = r#"
    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
    _:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
    _:b0 <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
    _:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> .
    "#;
    const DEANON_MAP: [(&str, &str); 4] = [
        ("_:e0", "<did:example:john>"),
        ("_:e1", "<http://example.org/vaccine/a>"),
        ("_:e2", "<http://example.org/vcred/00>"),
        ("_:e3", "<http://example.org/vicred/a>"),
    ];
    fn get_example_deanon_map_string() -> HashMap<String, String> {
        DEANON_MAP
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }
    fn get_example_deanon_map() -> HashMap<NamedOrBlankNode, Term> {
        get_deanon_map_from_string(&get_example_deanon_map_string()).unwrap()
    }
    const VP: &str = r#"
    _:c14n1 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n11 .
    _:c14n1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n11 .
    _:c14n1 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" _:c14n11 .
    _:c14n1 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n11 .
    _:c14n1 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> _:c14n11 .
    _:c14n10 <http://example.org/vocab/vaccine> _:c14n4 _:c14n5 .
    _:c14n10 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> _:c14n5 .
    _:c14n13 <http://example.org/vocab/isPatientOf> _:c14n10 _:c14n5 .
    _:c14n13 <http://schema.org/worksFor> _:c14n7 _:c14n5 .
    _:c14n13 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> _:c14n5 .
    _:c14n14 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:c14n5 .
    _:c14n14 <https://w3id.org/security#proof> _:c14n11 _:c14n5 .
    _:c14n14 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n13 _:c14n5 .
    _:c14n14 <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n5 .
    _:c14n14 <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n5 .
    _:c14n14 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> _:c14n5 .
    _:c14n2 <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n0 .
    _:c14n2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n0 .
    _:c14n2 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" _:c14n0 .
    _:c14n2 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n0 .
    _:c14n2 <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> _:c14n0 .
    _:c14n3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiablePresentation> .
    _:c14n3 <https://w3id.org/security#proof> _:c14n12 .
    _:c14n3 <https://www.w3.org/2018/credentials#verifiableCredential> _:c14n5 .
    _:c14n3 <https://www.w3.org/2018/credentials#verifiableCredential> _:c14n6 .
    _:c14n4 <http://schema.org/status> "active" _:c14n6 .
    _:c14n4 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccine> _:c14n6 .
    _:c14n7 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Organization> _:c14n5 .
    _:c14n8 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:c14n6 .
    _:c14n8 <https://w3id.org/security#proof> _:c14n0 _:c14n6 .
    _:c14n8 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n4 _:c14n6 .
    _:c14n8 <https://www.w3.org/2018/credentials#expirationDate> "2023-12-31T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n6 .
    _:c14n8 <https://www.w3.org/2018/credentials#issuanceDate> "2020-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n6 .
    _:c14n8 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer3> _:c14n6 .
    _:c14n9 <http://purl.org/dc/terms/created> "2023-09-21T11:36:23.663929856Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n12 .
    _:c14n9 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n12 .
    _:c14n9 <https://w3id.org/security#challenge> "abcde" _:c14n12 .
    _:c14n9 <https://w3id.org/security#cryptosuite> "bbs-termwise-proof-2023" _:c14n12 .
    _:c14n9 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n12 .
    _:c14n9 <https://w3id.org/security#proofValue> "uomFhWQnaAgAAAAAAAAAAiAvTWnfhK5FK9n4FTbueRNfjipNVS5MNyvEPc2IJOuvQ0C3fp8hCuAIRc1_Lhf-Atw-gSU7LG7ia71FC2ozwOABP3GLWPBmU3fwEu7ooM5PYmQt1U9zsIGB1RVtG-T8huOdclYb-wiZFb7of3H6cRIcy7ujTzwgeTisDURUIZ18uiU1d5waitcTMFppTyi2StbtPjPxCObRd68AaVop3K37J1HCIIr9FjynFecH-dn3druVBnHgpeY9bKuOnneAHAgAAAAAAAADFAMrFjLAwFzeCag9JnfvJa4sib8jnC3F-GVzu-pEVaQqLd9maCNxm4qe3qvHxhjo8svPmuMs4zGJLZ3h7FdpzlBmWzGSPL8_bZpAlEKSxwR5jxRI8gplwEN9rL_TunBFRPVTAmJH0s-4Z_0M42LTwJQAAAAAAAADmpxFadg9i_CvnVqqKKpe5DHLYPin12qA6wrZqF3usET07re5L_LAS1BgfnYtvAp6_-7fpQ_v_2YGnLO4ouWJBseiFcR7PYBxwGC7HdgGHM-Dq4yXDSQJRRQS0Onq-3SPVj0Emqqy5Prpm_NdLIi8jlLhtec1TobFLMMKxiKBFJm6X1TmNITbne8Zb4fGyVFw7VVHlgO8yz6gKDC4TcvcnMas_hU-65b_XrSi7yNsvW-hms1069AvacbXskBX7rCncX8e-bqJBDtnvVB8rOWbALk8sdn8mXIbKucO3KSddYrHohXEez2AccBgux3YBhzPg6uMlw0kCUUUEtDp6vt0jxyhevJbcHbchu617fw0K07-7unaVXP-Qxd0NFN0GO1Cx6IVxHs9gHHAYLsd2AYcz4OrjJcNJAlFFBLQ6er7dI85d36Xq0iNf_xqFAttV95nqPmEG0d_KGhnJsemmx4hHzl3fperSI1__GoUC21X3meo-YQbR38oaGcmx6abHiEex6IVxHs9gHHAYLsd2AYcz4OrjJcNJAlFFBLQ6er7dI85d36Xq0iNf_xqFAttV95nqPmEG0d_KGhnJsemmx4hHzl3fperSI1__GoUC21X3meo-YQbR38oaGcmx6abHiEfOXd-l6tIjX_8ahQLbVfeZ6j5hBtHfyhoZybHppseIR_nTD-EjxlwSJlRPVtOJ9Cq-G2eFd5d9y9xoRVW98vEod8cSVxq5B0R9iloenQr3cQjaXhKj0AYNBotZH02xQlHe4F2k7PxanS-tREDTxviA5QjQrq54mdF-6E8glu-ODMcoXryW3B23Ibute38NCtO_u7p2lVz_kMXdDRTdBjtQ702-cGYYqPreCy1VetrT_0F956exjmhf4ffZrO0auxI98x_AkdgFgm6wSV1LnkJ3cfVy7n5uRxGQ3nRYA0JoJPX47fF5HSDae4TxE9Ifh4erRTMRmP8e1wszyq4zTn0FhhvLx8m17KaLFj_WSi6QN-x_DuBncILmYS8RMCN4_gms3ZRpOnbHZyeusSASQf_HVjUxTAwnUw7evRwDDtGXJDxKRbHgljw6HpSXNyJKBACHWrMXsoxTMjaIqQ0NfSRY1Y9BJqqsuT66ZvzXSyIvI5S4bXnNU6GxSzDCsYigRSYOzIGG_xWlyKrgYn-0MR2qh49lq2Gr4e2H_UKoSjgFT81TCksS7oc2G5JmKn5udpHYWDcOyFU8H3jKvtvb38BK0fpR0B5u0xmPDecPPnndOuXueINPTVCwyOoXnkJaox1-4DKoKPel8efuFjMcYRVm0y5DwFkvfWNFaNnxsHU7NdWPQSaqrLk-umb810siLyOUuG15zVOhsUswwrGIoEUm0gFo3d0Q169csX-agPVv-lTnWPiBSjMnalSiSyVX5QHSAWjd3RDXr1yxf5qA9W_6VOdY-IFKMydqVKJLJVflAdIBaN3dENevXLF_moD1b_pU51j4gUozJ2pUokslV-UB0gFo3d0Q169csX-agPVv-lTnWPiBSjMnalSiSyVX5QHSAWjd3RDXr1yxf5qA9W_6VOdY-IFKMydqVKJLJVflAQCsfuTQjkFAt7HLPg5IlqNbtDUXlV8BSo1MO-TnkS5XZa7O2BcJjzR0fc8VHkioAx-ThPGRsf9IMPQU37SQH8fxpAf9irC-ghKxPvaH6Q1vKU8mmSikLMI7XcxstAyrghaUfEzS6V0G4bFYLJ86vyPi83tBGDDy_RLtN_er8NxgZUNyql_8ra_GRUpm62E09g2V3t1H_bL2FHMCfSok3__0xTGHSwbIgIvxnbpHADwih2jfLXmcN5_iDnFWVjVQwaMCAAAAAAAAABtEnFz-_fsWTa-SSiLsOtPKVAqI81CVVVlS8FoNMvxWw87N0t5OEqjlL8XwC_5lsHq5SaaNRHd7YK5DX2vMewCshM-m4EVeP4feH7p_12qH_sI5ME1L4JxDuFG962JrK-SZJiEGnAMwJOyu0B0ZV9kVAAAAAAAAAORW8JlO-6GI_HPv1qgITpvjmIFrjq5eyQORDYRLSwcFMeiHbCAvMYSrctuAmbaJCebGblJEW4wu4juvrcVDzD9k12E4-FoR04J32Pgf7pXME22Dx6Un5Bqcj0_l97X5HTmCaL92l3mE1Vkq1zi5anQkik1NkeqiXJKVANp8alM4U4igyyzi1twJQtj5Zw9ExVsohHko3hQA2kdiIleLxTpa84H8gYfOVdR03LO4OBs6iSSKIWDB55OQnWAXNw-YZ6Qbv2eP5Ue9wWhez9FFb6YoEr7xTLPAArX9Tq_NEFpT1Ep03asgrIPp0p7CU767k6hONY-m8vgJlqSPoS4cti8OzIGG_xWlyKrgYn-0MR2qh49lq2Gr4e2H_UKoSjgFTw7MgYb_FaXIquBif7QxHaqHj2WrYavh7Yf9QqhKOAVPB70w7NJVMYXUBb95-yRBNxhkzVaR4pNYaQ4_mezfdBAHvTDs0lUxhdQFv3n7JEE3GGTNVpHik1hpDj-Z7N90EA7MgYb_FaXIquBif7QxHaqHj2WrYavh7Yf9QqhKOAVPB70w7NJVMYXUBb95-yRBNxhkzVaR4pNYaQ4_mezfdBAHvTDs0lUxhdQFv3n7JEE3GGTNVpHik1hpDj-Z7N90EAe9MOzSVTGF1AW_efskQTcYZM1WkeKTWGkOP5ns33QQ4wYh-C5BSpRLBvMrrVj36YelFsp5y7Jq6zAvlkVICT3jBiH4LkFKlEsG8yutWPfph6UWynnLsmrrMC-WRUgJPeMGIfguQUqUSwbzK61Y9-mHpRbKecuyauswL5ZFSAk94wYh-C5BSpRLBvMrrVj36YelFsp5y7Jq6zAvlkVICT3jBiH4LkFKlEsG8yutWPfph6UWynnLsmrrMC-WRUgJPQEFAAAAAAAAAGFiY2RlAABhYoKkYWGLDQ8AAgMEBQYHCAphYhBhY4UAAQIDBGFkBaRhYYcCAwQFBgcIYWIJYWOFAAECAwRhZAU"^^<https://w3id.org/security#multibase> _:c14n12 .
    "#;

    #[test]
    fn derive_and_verify_proof_success() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed
        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();

        let vc_doc_1 = get_graph_from_ntriples(VC_1).unwrap();
        let vc_proof_1 = get_graph_from_ntriples(VC_PROOF_1).unwrap();
        let vc_1 = VerifiableCredential::new(vc_doc_1, vc_proof_1);

        let disclosed_vc_doc_1 = get_graph_from_ntriples(DISCLOSED_VC_1).unwrap();
        let disclosed_vc_proof_1 = get_graph_from_ntriples(DISCLOSED_VC_PROOF_1).unwrap();
        let disclosed_1 = VerifiableCredential::new(disclosed_vc_doc_1, disclosed_vc_proof_1);

        let vc_doc_2 = get_graph_from_ntriples(VC_2).unwrap();
        let vc_proof_2 = get_graph_from_ntriples(VC_PROOF_2).unwrap();
        let vc_2 = VerifiableCredential::new(vc_doc_2, vc_proof_2);

        let disclosed_vc_doc_2 = get_graph_from_ntriples(DISCLOSED_VC_2).unwrap();
        let disclosed_vc_proof_2 = get_graph_from_ntriples(DISCLOSED_VC_PROOF_2).unwrap();
        let disclosed_2 = VerifiableCredential::new(disclosed_vc_doc_2, disclosed_vc_proof_2);

        let vc_with_disclosed_1 = VcPair::new(vc_1, disclosed_1);
        let vc_with_disclosed_2 = VcPair::new(vc_2, disclosed_2);
        let vcs = vec![vc_with_disclosed_1, vc_with_disclosed_2];

        let deanon_map = get_example_deanon_map();

        let nonce = "abcde";

        let derived_proof =
            derive_proof(&mut rng, None, &vcs, &deanon_map, Some(nonce), &key_graph).unwrap();
        println!("derived_proof: {}", rdf_canon::serialize(&derived_proof));

        let verified = verify_proof(&mut rng, &derived_proof, Some(nonce), &key_graph);
        assert!(verified.is_ok(), "{:?}", verified)
    }

    #[test]
    fn derive_and_verify_proof_string_success() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed

        let vc_pairs = vec![
            VcPairString::new(VC_1, VC_PROOF_1, DISCLOSED_VC_1, DISCLOSED_VC_PROOF_1),
            VcPairString::new(VC_2, VC_PROOF_2, DISCLOSED_VC_2, DISCLOSED_VC_PROOF_2),
        ];

        let deanon_map = get_example_deanon_map_string();

        let nonce = "abcde";

        let derived_proof = derive_proof_string(
            &mut rng,
            None,
            &vc_pairs,
            &deanon_map,
            Some(nonce),
            KEY_GRAPH,
        )
        .unwrap();
        println!("derived_proof: {}", derived_proof);

        let verified = verify_proof_string(&mut rng, &derived_proof, Some(nonce), KEY_GRAPH);
        assert!(verified.is_ok(), "{:?}", verified)
    }

    #[test]
    fn verify_proof_success() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed
        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();
        let vp = get_dataset_from_nquads(VP).unwrap();
        let nonce = "abcde";
        let verified = verify_proof(&mut rng, &vp, Some(nonce), &key_graph);
        assert!(verified.is_ok(), "{:?}", verified)
    }

    #[test]
    fn verify_proof_string_success() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed
        let nonce = "abcde";
        let verified = verify_proof_string(&mut rng, VP, Some(nonce), KEY_GRAPH);
        assert!(verified.is_ok(), "{:?}", verified)
    }

    #[test]
    fn derive_and_verify_proof_without_nonce() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed
        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();

        let vc_doc_1 = get_graph_from_ntriples(VC_1).unwrap();
        let vc_proof_1 = get_graph_from_ntriples(VC_PROOF_1).unwrap();
        let vc_1 = VerifiableCredential::new(vc_doc_1, vc_proof_1);

        let disclosed_vc_doc_1 = get_graph_from_ntriples(DISCLOSED_VC_1).unwrap();
        let disclosed_vc_proof_1 = get_graph_from_ntriples(DISCLOSED_VC_PROOF_1).unwrap();
        let disclosed_1 = VerifiableCredential::new(disclosed_vc_doc_1, disclosed_vc_proof_1);

        let vc_doc_2 = get_graph_from_ntriples(VC_2).unwrap();
        let vc_proof_2 = get_graph_from_ntriples(VC_PROOF_2).unwrap();
        let vc_2 = VerifiableCredential::new(vc_doc_2, vc_proof_2);

        let disclosed_vc_doc_2 = get_graph_from_ntriples(DISCLOSED_VC_2).unwrap();
        let disclosed_vc_proof_2 = get_graph_from_ntriples(DISCLOSED_VC_PROOF_2).unwrap();
        let disclosed_2 = VerifiableCredential::new(disclosed_vc_doc_2, disclosed_vc_proof_2);

        let vc_with_disclosed_1 = VcPair::new(vc_1, disclosed_1);
        let vc_with_disclosed_2 = VcPair::new(vc_2, disclosed_2);
        let vcs = vec![vc_with_disclosed_1, vc_with_disclosed_2];

        let deanon_map = get_example_deanon_map();

        let nonce = None;

        let derived_proof =
            derive_proof(&mut rng, None, &vcs, &deanon_map, nonce, &key_graph).unwrap();

        let verified = verify_proof(&mut rng, &derived_proof, nonce, &key_graph);

        assert!(verified.is_ok(), "{:?}", verified)
    }

    #[test]
    fn derive_and_verify_proof_string_without_nonce() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed

        let vc_pairs = vec![
            VcPairString::new(VC_1, VC_PROOF_1, DISCLOSED_VC_1, DISCLOSED_VC_PROOF_1),
            VcPairString::new(VC_2, VC_PROOF_2, DISCLOSED_VC_2, DISCLOSED_VC_PROOF_2),
        ];

        let deanon_map = get_example_deanon_map_string();

        let nonce = None;

        let derived_proof =
            derive_proof_string(&mut rng, None, &vc_pairs, &deanon_map, nonce, KEY_GRAPH).unwrap();

        let verified = verify_proof_string(&mut rng, &derived_proof, nonce, KEY_GRAPH);

        assert!(verified.is_ok(), "{:?}", verified)
    }

    #[test]
    fn derive_without_nonce_and_verify_proof_with_nonce() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed
        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();

        let vc_doc_1 = get_graph_from_ntriples(VC_1).unwrap();
        let vc_proof_1 = get_graph_from_ntriples(VC_PROOF_1).unwrap();
        let vc_1 = VerifiableCredential::new(vc_doc_1, vc_proof_1);

        let disclosed_vc_doc_1 = get_graph_from_ntriples(DISCLOSED_VC_1).unwrap();
        let disclosed_vc_proof_1 = get_graph_from_ntriples(DISCLOSED_VC_PROOF_1).unwrap();
        let disclosed_1 = VerifiableCredential::new(disclosed_vc_doc_1, disclosed_vc_proof_1);

        let vc_doc_2 = get_graph_from_ntriples(VC_2).unwrap();
        let vc_proof_2 = get_graph_from_ntriples(VC_PROOF_2).unwrap();
        let vc_2 = VerifiableCredential::new(vc_doc_2, vc_proof_2);

        let disclosed_vc_doc_2 = get_graph_from_ntriples(DISCLOSED_VC_2).unwrap();
        let disclosed_vc_proof_2 = get_graph_from_ntriples(DISCLOSED_VC_PROOF_2).unwrap();
        let disclosed_2 = VerifiableCredential::new(disclosed_vc_doc_2, disclosed_vc_proof_2);

        let vc_with_disclosed_1 = VcPair::new(vc_1, disclosed_1);
        let vc_with_disclosed_2 = VcPair::new(vc_2, disclosed_2);
        let vcs = vec![vc_with_disclosed_1, vc_with_disclosed_2];

        let deanon_map = get_example_deanon_map();

        let derived_proof =
            derive_proof(&mut rng, None, &vcs, &deanon_map, None, &key_graph).unwrap();

        let nonce = "abcde";

        let verified = verify_proof(&mut rng, &derived_proof, Some(nonce), &key_graph);

        assert!(matches!(
            verified,
            Err(RDFProofsError::MissingChallengeInVP)
        ))
    }

    #[test]
    fn derive_without_nonce_and_verify_proof_with_nonce_string() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed
        let vc_pairs = vec![
            VcPairString::new(VC_1, VC_PROOF_1, DISCLOSED_VC_1, DISCLOSED_VC_PROOF_1),
            VcPairString::new(VC_2, VC_PROOF_2, DISCLOSED_VC_2, DISCLOSED_VC_PROOF_2),
        ];

        let deanon_map = get_example_deanon_map_string();

        let derived_proof =
            derive_proof_string(&mut rng, None, &vc_pairs, &deanon_map, None, KEY_GRAPH).unwrap();

        let nonce = "abcde";

        let verified = verify_proof_string(&mut rng, &derived_proof, Some(nonce), KEY_GRAPH);

        assert!(matches!(
            verified,
            Err(RDFProofsError::MissingChallengeInVP)
        ))
    }

    #[test]
    fn derive_with_nonce_and_verify_proof_without_nonce() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed
        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();

        let vc_doc_1 = get_graph_from_ntriples(VC_1).unwrap();
        let vc_proof_1 = get_graph_from_ntriples(VC_PROOF_1).unwrap();
        let vc_1 = VerifiableCredential::new(vc_doc_1, vc_proof_1);

        let disclosed_vc_doc_1 = get_graph_from_ntriples(DISCLOSED_VC_1).unwrap();
        let disclosed_vc_proof_1 = get_graph_from_ntriples(DISCLOSED_VC_PROOF_1).unwrap();
        let disclosed_1 = VerifiableCredential::new(disclosed_vc_doc_1, disclosed_vc_proof_1);

        let vc_doc_2 = get_graph_from_ntriples(VC_2).unwrap();
        let vc_proof_2 = get_graph_from_ntriples(VC_PROOF_2).unwrap();
        let vc_2 = VerifiableCredential::new(vc_doc_2, vc_proof_2);

        let disclosed_vc_doc_2 = get_graph_from_ntriples(DISCLOSED_VC_2).unwrap();
        let disclosed_vc_proof_2 = get_graph_from_ntriples(DISCLOSED_VC_PROOF_2).unwrap();
        let disclosed_2 = VerifiableCredential::new(disclosed_vc_doc_2, disclosed_vc_proof_2);

        let vc_with_disclosed_1 = VcPair::new(vc_1, disclosed_1);
        let vc_with_disclosed_2 = VcPair::new(vc_2, disclosed_2);
        let vcs = vec![vc_with_disclosed_1, vc_with_disclosed_2];

        let deanon_map = get_example_deanon_map();

        let nonce = "abcde";

        let derived_proof =
            derive_proof(&mut rng, None, &vcs, &deanon_map, Some(nonce), &key_graph).unwrap();

        let verified = verify_proof(&mut rng, &derived_proof, None, &key_graph);

        assert!(matches!(
            verified,
            Err(RDFProofsError::MissingChallengeInRequest)
        ))
    }

    #[test]
    fn derive_with_nonce_and_verify_proof_without_nonce_string() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed
        let vc_pairs = vec![
            VcPairString::new(VC_1, VC_PROOF_1, DISCLOSED_VC_1, DISCLOSED_VC_PROOF_1),
            VcPairString::new(VC_2, VC_PROOF_2, DISCLOSED_VC_2, DISCLOSED_VC_PROOF_2),
        ];

        let deanon_map = get_example_deanon_map_string();

        let nonce = "abcde";

        let derived_proof = derive_proof_string(
            &mut rng,
            None,
            &vc_pairs,
            &deanon_map,
            Some(nonce),
            KEY_GRAPH,
        )
        .unwrap();

        let verified = verify_proof_string(&mut rng, &derived_proof, None, KEY_GRAPH);

        assert!(matches!(
            verified,
            Err(RDFProofsError::MissingChallengeInRequest)
        ))
    }

    const DISCLOSED_VC_1_WITH_HIDDEN_LITERALS: &str = r#"
    _:e0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
    _:e0 <http://schema.org/name> _:e4 .
    _:e0 <http://example.org/vocab/isPatientOf> _:b0 .
    _:e0 <http://schema.org/worksFor> _:b1 .
    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
    _:b0 <http://example.org/vocab/vaccine> _:e1 .
    _:b0 <http://example.org/vocab/vaccinationDate> _:e5 .
    _:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Organization> .
    _:e2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
    _:e2 <https://www.w3.org/2018/credentials#credentialSubject> _:e0 .
    _:e2 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
    _:e2 <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:e2 <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    "#;
    const DEANON_MAP_WITH_HIDDEN_LITERAL: [(&str, &str); 2] = [
        ("_:e4", "\"John Smith\""),
        (
            "_:e5",
            "\"2022-01-01T00:00:00Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime>",
        ),
    ];
    fn get_example_deanon_map_string_with_hidden_literal() -> HashMap<String, String> {
        DEANON_MAP_WITH_HIDDEN_LITERAL
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }
    fn get_example_deanon_map_with_hidden_literal() -> HashMap<NamedOrBlankNode, Term> {
        get_deanon_map_from_string(&&get_example_deanon_map_string_with_hidden_literal()).unwrap()
    }

    #[test]
    fn derive_and_verify_proof_with_hidden_literals() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed
        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();

        let mut deanon_map = get_example_deanon_map();
        deanon_map.extend(get_example_deanon_map_with_hidden_literal());

        let vc_doc_1 = get_graph_from_ntriples(VC_1).unwrap();
        let vc_proof_1 = get_graph_from_ntriples(VC_PROOF_1).unwrap();
        let vc_1 = VerifiableCredential::new(vc_doc_1, vc_proof_1);

        let disclosed_vc_doc_1 =
            get_graph_from_ntriples(DISCLOSED_VC_1_WITH_HIDDEN_LITERALS).unwrap();
        let disclosed_vc_proof_1 = get_graph_from_ntriples(DISCLOSED_VC_PROOF_1).unwrap();
        let disclosed_1 = VerifiableCredential::new(disclosed_vc_doc_1, disclosed_vc_proof_1);

        let vc_with_disclosed_1 = VcPair::new(vc_1, disclosed_1);
        let vcs = vec![vc_with_disclosed_1];

        let nonce = "abcde";

        let derived_proof =
            derive_proof(&mut rng, None, &vcs, &deanon_map, Some(nonce), &key_graph).unwrap();
        println!("derived_proof: {}", rdf_canon::serialize(&derived_proof));

        let verified = verify_proof(&mut rng, &derived_proof, Some(nonce), &key_graph);
        assert!(verified.is_ok(), "{:?}", verified)
    }

    #[test]
    fn derive_and_verify_proof_string_with_hidden_literals() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed

        let vc_pairs = vec![VcPairString::new(
            VC_1,
            VC_PROOF_1,
            DISCLOSED_VC_1,
            DISCLOSED_VC_PROOF_1,
        )];

        let mut deanon_map = get_example_deanon_map_string();
        deanon_map.extend(get_example_deanon_map_string_with_hidden_literal());

        let nonce = "abcde";

        let derived_proof = derive_proof_string(
            &mut rng,
            None,
            &vc_pairs,
            &deanon_map,
            Some(nonce),
            KEY_GRAPH,
        )
        .unwrap();

        let verified = verify_proof_string(&mut rng, &derived_proof, Some(nonce), KEY_GRAPH);

        assert!(verified.is_ok(), "{:?}", verified)
    }

    #[test]
    fn derive_proof_failed_invalid_vc() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed
        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();

        let vc_ntriples = r#"
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

        let vc_doc = get_graph_from_ntriples(vc_ntriples).unwrap();
        let vc_proof = get_graph_from_ntriples(VC_PROOF_1).unwrap();
        let vc = VerifiableCredential::new(vc_doc, vc_proof);

        let disclosed_vc_doc = get_graph_from_ntriples(DISCLOSED_VC_1).unwrap();
        let disclosed_vc_proof = get_graph_from_ntriples(DISCLOSED_VC_PROOF_1).unwrap();
        let disclosed = VerifiableCredential::new(disclosed_vc_doc, disclosed_vc_proof);

        let vc_with_disclosed = VcPair::new(vc, disclosed);
        let vcs = vec![vc_with_disclosed];

        let deanon_map = get_example_deanon_map();

        let nonce = "abcde";

        let derived_proof =
            derive_proof(&mut rng, None, &vcs, &deanon_map, Some(nonce), &key_graph);
        assert!(matches!(
            derived_proof,
            Err(RDFProofsError::BBSPlus(
                bbs_plus::prelude::BBSPlusError::InvalidSignature
            ))
        ))
    }

    #[test]
    fn derive_proof_string_failed_invalid_vc() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed

        let vc_pairs = vec![VcPairString::new(
            VC_1_MODIFIED,
            VC_PROOF_1,
            DISCLOSED_VC_1,
            DISCLOSED_VC_PROOF_1,
        )];

        let deanon_map = get_example_deanon_map_string();

        let nonce = "abcde";

        let derived_proof = derive_proof_string(
            &mut rng,
            None,
            &vc_pairs,
            &deanon_map,
            Some(nonce),
            KEY_GRAPH,
        );

        assert!(matches!(
            derived_proof,
            Err(RDFProofsError::BBSPlus(
                bbs_plus::prelude::BBSPlusError::InvalidSignature
            ))
        ))
    }
}
