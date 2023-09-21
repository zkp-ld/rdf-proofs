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
    blind_sig_request, blind_sig_request_string, blind_sign, blind_sign_string, blind_verify,
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
    _:c14n1 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n12 .
    _:c14n1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n12 .
    _:c14n1 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" _:c14n12 .
    _:c14n1 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n12 .
    _:c14n1 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> _:c14n12 .
    _:c14n10 <http://example.org/vocab/vaccine> _:c14n4 _:c14n5 .
    _:c14n10 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> _:c14n5 .
    _:c14n11 <http://purl.org/dc/terms/created> "2023-09-19T11:52:13.344145635Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n6 .
    _:c14n11 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n6 .
    _:c14n11 <https://w3id.org/security#challenge> "abcde" _:c14n6 .
    _:c14n11 <https://w3id.org/security#cryptosuite> "bbs-termwise-proof-2023" _:c14n6 .
    _:c14n11 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n6 .
    _:c14n11 <https://w3id.org/security#proofValue> "uomFhWQnaAgAAAAAAAAAAj3pRuKqpHtsa0xziKwrLZIhG-U0ycYp_moex7dl1Y5p5NZuA5J1Q6ubMTTVIiXOytWS3aj5pIdc-3G571tngU4zh29QTHUgl4tJ12wBVSn6bUFLcvlTS9g2kyABgxClRpODMiCbHb2h83RBdvqcW9m-LlKG8rUbrUOhJXUMSPUvJzxmGuwKIZkbNhBc8KbWLj-sQe1GCo8fE-30hBBgsOtO_WZrnuBm6COIPGPcIg-feVOprZiG9DrgQT9rHerjKAgAAAAAAAAB2t2flGvbGCAXAnvgmZ2pd9SwdwE3sFCUVQ813PhkjSgdNfBrATCRC50LekfDB3am9peay3FphlBN4vU0acZsDj7yIdhcBfXOJ4lRktyApz1axji5vP4pjtr0YXbnlJYJQbGddU2sFhfro3-0awRfGJQAAAAAAAAA6SfboKj6RRx5BT7QIWJ9zVbfbacNUmtiW7sqy86OnK3ipeb_RnZENbKqHarJwl4vCvGUDxPnUB2bEQ2HSX7YERO5OpcOW-7Rak_g3LIoo-_b3opn6i1hdDzOqCvc4kD2MYycMpBVNvN6kf9ItVFgB9-xiFxIXecupWWqNkfC1IgGdnm0y6dB_ZkEmUqc79iNSYhBZuDGJ23I5Av6P7KlBgj1T8CYvS9oKQ--eM492wzr5N5H3JM5c5aQIqR7Nw1XYgGyvvkVtm69ypDz3Xp7ThIt3uTPkKZQgtmvWA1D6WETuTqXDlvu0WpP4NyyKKPv296KZ-otYXQ8zqgr3OJA9wyZ_tdDWew_SWxM8NOVleEYGt5XSG42_caM00Juv3FdE7k6lw5b7tFqT-Dcsiij79veimfqLWF0PM6oK9ziQPb9jZbHUDy-L-ANUBNoMnnVeR3kDAoPv2XRkmSY_dy1zv2NlsdQPL4v4A1QE2gyedV5HeQMCg-_ZdGSZJj93LXNE7k6lw5b7tFqT-Dcsiij79veimfqLWF0PM6oK9ziQPb9jZbHUDy-L-ANUBNoMnnVeR3kDAoPv2XRkmSY_dy1zv2NlsdQPL4v4A1QE2gyedV5HeQMCg-_ZdGSZJj93LXO_Y2Wx1A8vi_gDVATaDJ51Xkd5AwKD79l0ZJkmP3ctc_XRMNpdwLpq1vS0FohhUNBEZmOktFYL-ogubBF8m5Mwx1kmwvItbV6xwyICBRqAhlWUQTxYKY9cMf3XDQPcawno3bY4yCwyt7LY5Uls6qTAFCua45NuypzQgcADlJhxQsMmf7XQ1nsP0lsTPDTlZXhGBreV0huNv3GjNNCbr9xXpiGkVmCBO3gDSrBPXAz93aSx3EX2UUB5PyGCiPZqKw_m4ZB8MHTnoatMfrxd_vIdK7hdWfNFul_ULap8cB5uMcXxZiEKwEyputX-gyW271pg2ODBHpyEfvNcUuYt9BQlPe-wrcMegCSwVMLQLGC5FU-0A36sM1oAwFi5CyzIbgam0Ez8YaXyBmCaVVcbRHs8nm9KPxw3ni-XTIPdukctGY4dCTNGaZIXwJa8bFhGypJ0tF1pJ7uyayu-PVvDNRACjGMnDKQVTbzepH_SLVRYAffsYhcSF3nLqVlqjZHwtSLPXzXchDAsN0B_Q1hGfzINZGHAZ9rXKU135OARPSLjQ4Qn8DAMVxu0P9DpJGCgn287jSysDBkUOdbzZrfkLzFHMa65ct2xcuwNZYXF8JnpJDnn518gx_WWM-7_2oqt2w5TkYWq2MYl9WKzXEGj1Zd4SC6Q4Gk7fhV-ZZmagJEwKIxjJwykFU283qR_0i1UWAH37GIXEhd5y6lZao2R8LUi5_N8dI68FU5h1H34Gm4kF0svbKxUWnVCmgKysIXZbD7n83x0jrwVTmHUffgabiQXSy9srFRadUKaArKwhdlsPufzfHSOvBVOYdR9-BpuJBdLL2ysVFp1QpoCsrCF2Ww-5_N8dI68FU5h1H34Gm4kF0svbKxUWnVCmgKysIXZbD7n83x0jrwVTmHUffgabiQXSy9srFRadUKaArKwhdlsPgCOC48cz-D5rKxjW19YQAeL_Bn0VZeLmJi7I4Ul4k9O_Vfh2igEAYWkub9yxHxBFeOTkwSVSg-ECCfwuvvqRWfYO6mj6umb3SvlPeDOyCa0wYVo9YvDF0-jsc8Il2U-NjaLE77fgpyqVBo08eJmevvvjNfYUg9Ct3plY6VgbVCMZU6jawwdQIWKB3Y-5ts1UbWmBVIHO7RVu9esGppNpCyvDlgigWRSSplZdX8Owgjl9RApUQ2KCU9Qvgc_VoJq33gCAAAAAAAAAMz6OXyMQ5IIG-3GMwC2qWZU9gTZeFWeCfB7YeRQuQk46Q7qzTRr5c1maBQdpU9S_4ZtCV3fpC-aPPDi4RERMkCnPZ0Se30_xf5DeAwY6Bh3oLVmE5e-1X5YMVKfOSZDd5pbqxntzYEnA_Zz1AETSgYVAAAAAAAAABzJX81dMnvwMh2kM1n9dq-WedfBtga0P3X7cg-gruprrYFcXH2LUI_R59jIzSHcSjAPLnF23MNOoDks_gZSszAlaxWOfXWYQRgWudGxO6sv8D7egx5ULHqLdu1O6p_XEkrqV0RHXU-uJ0XaOA1OGx7p6ibtBZ1-dLTBYcQuK4k2EHLVeCQxzyY8QdBPgcu3eTkwAe3JOrAHNOuCGX7_xQYbhzVSB6JVxGkTvYxKhjCdZfbk3djtL_N_hP6AKfl1XPSt0tJnWq3X9aEmszlV-Lp1zKAbAgxJUuBvzZ2DO4MLpuKuXMzjLI3KyrLA6eri5yOfrAcI6WMIU37FIespdkvPXzXchDAsN0B_Q1hGfzINZGHAZ9rXKU135OARPSLjQ89fNdyEMCw3QH9DWEZ_Mg1kYcBn2tcpTXfk4BE9IuNDNk2_cs9iVCnAOHbYBjFyoN1pmwR8uj5Y3C0T7wSodRk2Tb9yz2JUKcA4dtgGMXKg3WmbBHy6PljcLRPvBKh1Gc9fNdyEMCw3QH9DWEZ_Mg1kYcBn2tcpTXfk4BE9IuNDNk2_cs9iVCnAOHbYBjFyoN1pmwR8uj5Y3C0T7wSodRk2Tb9yz2JUKcA4dtgGMXKg3WmbBHy6PljcLRPvBKh1GTZNv3LPYlQpwDh22AYxcqDdaZsEfLo-WNwtE-8EqHUZdqUe0sBve1wU-lghuRS6lX96JLx4a0EGu2OMaphLZzF2pR7SwG97XBT6WCG5FLqVf3okvHhrQQa7Y4xqmEtnMXalHtLAb3tcFPpYIbkUupV_eiS8eGtBBrtjjGqYS2cxdqUe0sBve1wU-lghuRS6lX96JLx4a0EGu2OMaphLZzF2pR7SwG97XBT6WCG5FLqVf3okvHhrQQa7Y4xqmEtnMQEFAAAAAAAAAGFiY2RlAABhYoKkYWGLDQ8AAgMEBQYHCAphYhBhY4UAAQIDBGFkBaRhYYcCAwQFBgcIYWIJYWOFAAECAwRhZAU"^^<https://w3id.org/security#multibase> _:c14n6 .
    _:c14n13 <http://example.org/vocab/isPatientOf> _:c14n10 _:c14n5 .
    _:c14n13 <http://schema.org/worksFor> _:c14n8 _:c14n5 .
    _:c14n13 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> _:c14n5 .
    _:c14n14 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:c14n5 .
    _:c14n14 <https://w3id.org/security#proof> _:c14n12 _:c14n5 .
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
    _:c14n3 <https://w3id.org/security#proof> _:c14n6 .
    _:c14n3 <https://www.w3.org/2018/credentials#verifiableCredential> _:c14n5 .
    _:c14n3 <https://www.w3.org/2018/credentials#verifiableCredential> _:c14n7 .
    _:c14n4 <http://schema.org/status> "active" _:c14n7 .
    _:c14n4 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccine> _:c14n7 .
    _:c14n8 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Organization> _:c14n5 .
    _:c14n9 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:c14n7 .
    _:c14n9 <https://w3id.org/security#proof> _:c14n0 _:c14n7 .
    _:c14n9 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n4 _:c14n7 .
    _:c14n9 <https://www.w3.org/2018/credentials#expirationDate> "2023-12-31T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n7 .
    _:c14n9 <https://www.w3.org/2018/credentials#issuanceDate> "2020-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n7 .
    _:c14n9 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer3> _:c14n7 .
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
            derive_proof(&mut rng, &vcs, &deanon_map, Some(nonce), &key_graph).unwrap();
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

        let derived_proof =
            derive_proof_string(&mut rng, &vc_pairs, &deanon_map, Some(nonce), KEY_GRAPH).unwrap();
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

        let derived_proof = derive_proof(&mut rng, &vcs, &deanon_map, nonce, &key_graph).unwrap();

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
            derive_proof_string(&mut rng, &vc_pairs, &deanon_map, nonce, KEY_GRAPH).unwrap();

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

        let derived_proof = derive_proof(&mut rng, &vcs, &deanon_map, None, &key_graph).unwrap();

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
            derive_proof_string(&mut rng, &vc_pairs, &deanon_map, None, KEY_GRAPH).unwrap();

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
            derive_proof(&mut rng, &vcs, &deanon_map, Some(nonce), &key_graph).unwrap();

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

        let derived_proof =
            derive_proof_string(&mut rng, &vc_pairs, &deanon_map, Some(nonce), KEY_GRAPH).unwrap();

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
            derive_proof(&mut rng, &vcs, &deanon_map, Some(nonce), &key_graph).unwrap();
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

        let derived_proof =
            derive_proof_string(&mut rng, &vc_pairs, &deanon_map, Some(nonce), KEY_GRAPH).unwrap();

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

        let derived_proof = derive_proof(&mut rng, &vcs, &deanon_map, Some(nonce), &key_graph);
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

        let derived_proof =
            derive_proof_string(&mut rng, &vc_pairs, &deanon_map, Some(nonce), KEY_GRAPH);

        assert!(matches!(
            derived_proof,
            Err(RDFProofsError::BBSPlus(
                bbs_plus::prelude::BBSPlusError::InvalidSignature
            ))
        ))
    }
}
