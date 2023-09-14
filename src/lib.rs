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

pub use derive_proof::{derive_proof, derive_proof_string};
pub use key_graph::KeyGraph;
pub use signature::{sign, sign_string, verify, verify_string};
pub use vc::{VcPair, VcPairString, VerifiableCredential};
pub use verify_proof::{verify_proof, verify_proof_string};

#[cfg(test)]
mod tests {
    use crate::{
        context::PROOF_VALUE, derive_proof, derive_proof::get_deanon_map_from_string,
        derive_proof_string, error::RDFProofsError, sign, sign_string, verify, verify_proof,
        verify_proof_string, verify_string, KeyGraph, VcPair, VcPairString, VerifiableCredential,
    };
    use ark_bls12_381::Bls12_381;
    use ark_serialize::CanonicalDeserialize;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use bbs_plus::prelude::SignatureG1 as BBSSignatureG1;
    use oxrdf::{Dataset, Graph, NamedOrBlankNode, Term, TermRef};
    use oxttl::{NQuadsParser, NTriplesParser};
    use std::{collections::HashMap, io::Cursor};

    pub(crate) const KEY_GRAPH_NTRIPLES: &str = r#"
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

    pub(crate) fn get_graph_from_ntriples_str(ntriples: &str) -> Graph {
        Graph::from_iter(
            NTriplesParser::new()
                .parse_read(Cursor::new(ntriples))
                .map(|x| x.unwrap()),
        )
    }

    pub(crate) fn get_dataset_from_nquads_str(nquads: &str) -> Dataset {
        Dataset::from_iter(
            NQuadsParser::new()
                .parse_read(Cursor::new(nquads))
                .map(|x| x.unwrap()),
        )
    }

    pub(crate) fn print_signature(vc: &VerifiableCredential) {
        let proof_value_triple = vc.proof.triples_for_predicate(PROOF_VALUE).next().unwrap();
        if let TermRef::Literal(v) = proof_value_triple.object {
            let proof_value = v.value();
            let (_, proof_value_bytes) = multibase::decode(proof_value).unwrap();
            let signature =
                BBSSignatureG1::<Bls12_381>::deserialize_compressed(&*proof_value_bytes).unwrap();
            println!("decoded signature:\n{:#?}\n", signature);
        }
    }

    // tests for sign & verify

    const VC_NTRIPLES_1: &str = r#"
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
    const VC_PROOF_NTRIPLES_WITHOUT_PROOFVALUE_1: &str = r#"
    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
    _:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
    _:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
    _:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
    "#;
    const VC_PROOF_NTRIPLES_1: &str = r#"
    _:b0 <https://w3id.org/security#proofValue> "uqIjm2ha4dq0-ftyWfevkWKuHWnC9vKQvsUlARU-16hybNr2X3WLMSnLJWP5r3OSLnHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
    _:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
    _:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
    _:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
    "#;
    const VC_NTRIPLES_1_MODIFIED: &str = r#"
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
    const VC_PROOF_NTRIPLES_1_MODIFIED: &str = r#"
    _:b0 <https://w3id.org/security#proofValue> "uqIjm2ha4dq0-ftyWfevkWKuHWnC9vKQvsUlARU-16hybNr2X3WLMSnLJWP5r3OSLnHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
    _:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
    _:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
    _:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer1#bls12_381-g2-pub001> . # the other issuer's pk
    "#;

    #[test]
    fn sign_and_verify_success() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let key_graph: KeyGraph = get_graph_from_ntriples_str(KEY_GRAPH_NTRIPLES).into();
        let unsecured_document = get_graph_from_ntriples_str(VC_NTRIPLES_1);
        let proof_config = get_graph_from_ntriples_str(VC_PROOF_NTRIPLES_WITHOUT_PROOFVALUE_1);
        let mut vc = VerifiableCredential::new(unsecured_document, proof_config);
        sign(&mut rng, &mut vc, &key_graph).unwrap();
        println!("vc: {}", vc);
        print_signature(&vc);
        assert!(verify(&vc, &key_graph).is_ok())
    }

    #[test]
    fn sign_and_verify_string_success() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let proof_value = sign_string(
            &mut rng,
            VC_NTRIPLES_1,
            VC_PROOF_NTRIPLES_WITHOUT_PROOFVALUE_1,
            KEY_GRAPH_NTRIPLES,
        )
        .unwrap();

        let vc_proof_with_proofvalue = format!(
            r#"{}
        _:b0 <https://w3id.org/security#proofValue> "{}"^^<https://w3id.org/security#multibase> .
        "#,
            VC_PROOF_NTRIPLES_WITHOUT_PROOFVALUE_1, proof_value
        );

        assert!(verify_string(VC_NTRIPLES_1, &vc_proof_with_proofvalue, KEY_GRAPH_NTRIPLES).is_ok())
    }

    #[test]
    fn verify_success() {
        let key_graph: KeyGraph = get_graph_from_ntriples_str(KEY_GRAPH_NTRIPLES).into();
        let unsecured_document = get_graph_from_ntriples_str(VC_NTRIPLES_1);
        let signed_proof_config = get_graph_from_ntriples_str(VC_PROOF_NTRIPLES_1);
        let vc = VerifiableCredential::new(unsecured_document, signed_proof_config);
        let verified = verify(&vc, &key_graph);
        assert!(verified.is_ok())
    }

    #[test]
    fn verify_string_success() {
        assert!(verify_string(VC_NTRIPLES_1, VC_PROOF_NTRIPLES_1, KEY_GRAPH_NTRIPLES).is_ok())
    }

    #[test]
    fn verify_failed_modified_document() {
        let key_graph: KeyGraph = get_graph_from_ntriples_str(KEY_GRAPH_NTRIPLES).into();
        let unsecured_document = get_graph_from_ntriples_str(VC_NTRIPLES_1_MODIFIED);
        let signed_proof_config = get_graph_from_ntriples_str(VC_PROOF_NTRIPLES_1);
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
        let verified = verify_string(
            VC_NTRIPLES_1_MODIFIED,
            VC_PROOF_NTRIPLES_1,
            KEY_GRAPH_NTRIPLES,
        );
        assert!(matches!(
            verified,
            Err(RDFProofsError::BBSPlus(
                bbs_plus::prelude::BBSPlusError::InvalidSignature
            ))
        ))
    }

    #[test]
    fn verify_failed_invalid_pk() {
        let key_graph: KeyGraph = get_graph_from_ntriples_str(KEY_GRAPH_NTRIPLES).into();
        let unsecured_document = get_graph_from_ntriples_str(VC_NTRIPLES_1);
        let signed_proof_config = get_graph_from_ntriples_str(VC_PROOF_NTRIPLES_1_MODIFIED);
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
        let verified = verify_string(
            VC_NTRIPLES_1,
            VC_PROOF_NTRIPLES_1_MODIFIED,
            KEY_GRAPH_NTRIPLES,
        );
        assert!(matches!(
            verified,
            Err(RDFProofsError::BBSPlus(
                bbs_plus::prelude::BBSPlusError::InvalidSignature
            ))
        ))
    }

    // tests for derive_proof & verify_proof

    const VC_NTRIPLES_2: &str = r#"
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
    const VC_PROOF_NTRIPLES_2: &str = r#"
    _:b0 <https://w3id.org/security#proofValue> "utRsO4PnUVwYae2BpwXQ74zFcLgBhuvJ2xBzw0gOwlRRvG4CoPPhRxg1jarO-zYNQnHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
    _:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
    _:b0 <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
    _:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> .
    "#;
    const DISCLOSED_VC_NTRIPLES_1: &str = r#"
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
    const DISCLOSED_VC_PROOF_NTRIPLES_1: &str = r#"
    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
    _:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
    _:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
    _:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
    "#;
    const DISCLOSED_VC_NTRIPLES_2: &str = r#"
    _:e1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccine> .
    _:e1 <http://schema.org/status> "active" .
    _:e3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
    _:e3 <https://www.w3.org/2018/credentials#credentialSubject> _:e1 .
    _:e3 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer3> .
    _:e3 <https://www.w3.org/2018/credentials#issuanceDate> "2020-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:e3 <https://www.w3.org/2018/credentials#expirationDate> "2023-12-31T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    "#;
    const DISCLOSED_VC_PROOF_NTRIPLES_2: &str = r#"
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
    const VP_NQUADS: &str = r#"
    _:c14n10 <http://example.org/vocab/vaccine> _:c14n5 _:c14n6 .
    _:c14n10 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> _:c14n6 .
    _:c14n12 <http://purl.org/dc/terms/created> "2023-09-14T12:48:56.852413787Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n1 .
    _:c14n12 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n1 .
    _:c14n12 <https://w3id.org/security#challenge> "abcde" _:c14n1 .
    _:c14n12 <https://w3id.org/security#cryptosuite> "bbs-termwise-proof-2023" _:c14n1 .
    _:c14n12 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n1 .
    _:c14n12 <https://w3id.org/security#proofValue> "uomVwcm9vZlkJ2gIAAAAAAAAAAI96UbiqqR7bGtMc4isKy2SIRvlNMnGKf5qHse3ZdWOaeTWbgOSdUOrmzE01SIlzsrVkt2o-aSHXPtxue9bZ4FOM4dvUEx1IJeLSddsAVUp-m1BS3L5U0vYNpMgAYMQpUaTgzIgmx29ofN0QXb6nFvZvi5ShvK1G61DoSV1DEj1Lyc8ZhrsCiGZGzYQXPCm1i4_rEHtRgqPHxPt9IQQYLDrTv1ma57gZugjiDxj3CIPn3lTqa2YhvQ64EE_ax3q4ygIAAAAAAAAAWL6fScreFUDNQwfmEh21baSp_fGgmLJ6tSYHQN-_6WtFADIiFIM9656JXxVF-jJW3sqtImKMEuE8P79uL6UzPqvhlEiyzHuCns7cgcLrlGTCDfBcbf_bQ8XMKlACcr7yHI65ImcY5-usSRBT9m3cSyUAAAAAAAAACWylJlERihdXI7-lSqw_x_--rAP4J-phuBXKnx2GHiqisCJy05ayYHvH8NX_zOU3XuPhwE5MjVq5WPAwtHVpHibRwKbSIDRkp66dRzY1hwbsOzhTDF00BQ3s3wFxZxYUyqmJp9yVCfZ7yDjMvy-z7HCEX_82BLu77WNMXoQz0Ds-mAvrtpXKpK8kzfBnXAeCr6FFbXtX9FniapWKGotuCKTGOl02epJYv824A2TY4CF1MV8u14TDu81PnAst4RBeJTOWSkut0DTWC6hsz6F2RRrOXrsaM7jw5gbP92H5c2Em0cCm0iA0ZKeunUc2NYcG7Ds4UwxdNAUN7N8BcWcWFEwtFM6RJ5LxLYYx8Fzpgl8cg7l5m2NY8I3ddF2pXMBSJtHAptIgNGSnrp1HNjWHBuw7OFMMXTQFDezfAXFnFhRdkGSQ_VnNIN9Qy5gq13c4ezRWOq2Fqny_i9xxSuTuOl2QZJD9Wc0g31DLmCrXdzh7NFY6rYWqfL-L3HFK5O46JtHAptIgNGSnrp1HNjWHBuw7OFMMXTQFDezfAXFnFhRdkGSQ_VnNIN9Qy5gq13c4ezRWOq2Fqny_i9xxSuTuOl2QZJD9Wc0g31DLmCrXdzh7NFY6rYWqfL-L3HFK5O46XZBkkP1ZzSDfUMuYKtd3OHs0Vjqthap8v4vccUrk7jp-2MXyHhHRTDIf08qwZW23GuNliH2e1iqlaKyeiUh3K-niDS8CebTcZU7sZjVj6uSPzGjZN4mEuxmoa3AR8LgRkkqhs6tgPoBHflmHhlnJ0TaXWiFgUunfi6Mw1p3ZTnFMLRTOkSeS8S2GMfBc6YJfHIO5eZtjWPCN3XRdqVzAUt92i5EP3U24AXQRUfbiUAvUspILkEeNfxYZnxB06cUowHrVXHJiXhOf0okBQLohUF81d7y1e-EweE1MGfFrVCbFFrFa_wKjSfIgIlN7NYRI2bFlfUToSjVKZLmR1Es5VnZEmOhyepJkrn4j0sY2DUN-tblDRimnBpdQ1pOpRgkg9wNxzI63UfIMnnV-0I2o0ZLlcVc0kH7CTcGyUBGfK29ywHWAHsD-1Ou6-0oQzoPYZ1SxEy2zq91sBlBy0VGICMqpiafclQn2e8g4zL8vs-xwhF__NgS7u-1jTF6EM9A7H7nVVVS8cOLn6c2tqHFkHJEd6IHWKSzfyf6GFB95z0O9fNdru7It9D36Sib6dvOcao7icaYOYT-t64M_Yq7LYHi4WVarIREIX-2y-8tRVvwh-zUpBMTXMoBIRYvv0ZVRGUMM8iHvjcaJ7nlCDi5PsOpJlXGnmB9pZQ2PZ27ybznKqYmn3JUJ9nvIOMy_L7PscIRf_zYEu7vtY0xehDPQO-uGUnnyp7PoM-ChHzGCE1qi3C1KGLWiwl4UBtLCAwU564ZSefKns-gz4KEfMYITWqLcLUoYtaLCXhQG0sIDBTnrhlJ58qez6DPgoR8xghNaotwtShi1osJeFAbSwgMFOeuGUnnyp7PoM-ChHzGCE1qi3C1KGLWiwl4UBtLCAwU564ZSefKns-gz4KEfMYITWqLcLUoYtaLCXhQG0sIDBTkAjguPHM_g-aysY1tfWEAHi_wZ9FWXi5iYuyOFJeJPTv1X4dooBAGFpLm_csR8QRXjk5MElUoPhAgn8Lr76kVn2Dupo-rpm90r5T3gzsgmtMGFaPWLwxdPo7HPCJdlPjY2ixO-34KcqlQaNPHiZnr774zX2FIPQrd6ZWOlYG1QjGVOo2sMHUCFigd2PubbNVG1pgVSBzu0VbvXrBqaTaQsrw5YIoFkUkqZWXV_DsII5fUQKVENiglPUL4HP1aCat94AgAAAAAAAACuAXLgOyzhP-NwLyHsa_R2A3PlCswBPF-QX5us8V_QWT5BEW-5RzPSxGfDl9ZbKdR1WGVYjRPZRes15Ud-twJEpz2dEnt9P8X-Q3gMGOgYd6C1ZhOXvtV-WDFSnzkmQ3eaW6sZ7c2BJwP2c9QBE0oGFQAAAAAAAAAgjrLQ_ER09q92TKdGOj-fTyKCmW_Qr4vgl9p6Ar8VFfAKrvu1fZZO0NdyFcyPKoNzAyzRBCUnrDpt9--suZQsdcS1B00B3ey_gEMnFC7dPh37BZ4api4M3pCTUcz2wxIFI7qePf83PCzSMit5rI9ffdDzO1LKpEehtJhKzLSqI_6EOGhqjWwR02HThRlKWg1h_o2T3zhUb721OJAMHQYaa-DVy9Ytmm8RfkfirHhirJKyDPjUPzKF0p6kgwtQYlwWN7o_d6X0Vaos8BdqnmIZsATIuOFrPrHIGmEAkk_QE7l_sF3_3unDXNXRg7JT1TmFFwDvbNnLqSgn51QmsjonH7nVVVS8cOLn6c2tqHFkHJEd6IHWKSzfyf6GFB95z0MfudVVVLxw4ufpza2ocWQckR3ogdYpLN_J_oYUH3nPQ9QXg67xZZu5POD8e051qTjFMwjVwB3eUSQ8ZLX1nxIX1BeDrvFlm7k84Px7TnWpOMUzCNXAHd5RJDxktfWfEhcfudVVVLxw4ufpza2ocWQckR3ogdYpLN_J_oYUH3nPQ9QXg67xZZu5POD8e051qTjFMwjVwB3eUSQ8ZLX1nxIX1BeDrvFlm7k84Px7TnWpOMUzCNXAHd5RJDxktfWfEhfUF4Ou8WWbuTzg_HtOdak4xTMI1cAd3lEkPGS19Z8SF_TbWASPcaNHrGaMFp2NZSKhXmnFV9q_b8sgVcLnGr1H9NtYBI9xo0esZowWnY1lIqFeacVX2r9vyyBVwucavUf021gEj3GjR6xmjBadjWUioV5pxVfav2_LIFXC5xq9R_TbWASPcaNHrGaMFp2NZSKhXmnFV9q_b8sgVcLnGr1H9NtYBI9xo0esZowWnY1lIqFeacVX2r9vyyBVwucavUcBBQAAAAAAAABhYmNkZQAAaWluZGV4X21hcIKkYTGLDQ8AAgMEBQYHCAphMhBhM4UAAQIDBGE0BaRhMYcCAwQFBgcIYTIJYTOFAAECAwRhNAU"^^<https://w3id.org/security#multibase> _:c14n1 .
    _:c14n13 <http://example.org/vocab/isPatientOf> _:c14n10 _:c14n6 .
    _:c14n13 <http://schema.org/worksFor> _:c14n8 _:c14n6 .
    _:c14n13 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> _:c14n6 .
    _:c14n14 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:c14n6 .
    _:c14n14 <https://w3id.org/security#proof> _:c14n11 _:c14n6 .
    _:c14n14 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n13 _:c14n6 .
    _:c14n14 <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n6 .
    _:c14n14 <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n6 .
    _:c14n14 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> _:c14n6 .
    _:c14n2 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n11 .
    _:c14n2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n11 .
    _:c14n2 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" _:c14n11 .
    _:c14n2 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n11 .
    _:c14n2 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> _:c14n11 .
    _:c14n3 <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n0 .
    _:c14n3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n0 .
    _:c14n3 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" _:c14n0 .
    _:c14n3 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n0 .
    _:c14n3 <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> _:c14n0 .
    _:c14n4 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiablePresentation> .
    _:c14n4 <https://w3id.org/security#proof> _:c14n1 .
    _:c14n4 <https://www.w3.org/2018/credentials#verifiableCredential> _:c14n6 .
    _:c14n4 <https://www.w3.org/2018/credentials#verifiableCredential> _:c14n7 .
    _:c14n5 <http://schema.org/status> "active" _:c14n7 .
    _:c14n5 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccine> _:c14n7 .
    _:c14n8 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Organization> _:c14n6 .
    _:c14n9 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:c14n7 .
    _:c14n9 <https://w3id.org/security#proof> _:c14n0 _:c14n7 .
    _:c14n9 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n5 _:c14n7 .
    _:c14n9 <https://www.w3.org/2018/credentials#expirationDate> "2023-12-31T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n7 .
    _:c14n9 <https://www.w3.org/2018/credentials#issuanceDate> "2020-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n7 .
    _:c14n9 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer3> _:c14n7 .
    "#;

    #[test]
    fn derive_and_verify_proof_success() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed
        let key_graph: KeyGraph = get_graph_from_ntriples_str(KEY_GRAPH_NTRIPLES).into();

        let vc_doc_1 = get_graph_from_ntriples_str(VC_NTRIPLES_1);
        let vc_proof_1 = get_graph_from_ntriples_str(VC_PROOF_NTRIPLES_1);
        let vc_1 = VerifiableCredential::new(vc_doc_1, vc_proof_1);

        let disclosed_vc_doc_1 = get_graph_from_ntriples_str(DISCLOSED_VC_NTRIPLES_1);
        let disclosed_vc_proof_1 = get_graph_from_ntriples_str(DISCLOSED_VC_PROOF_NTRIPLES_1);
        let disclosed_1 = VerifiableCredential::new(disclosed_vc_doc_1, disclosed_vc_proof_1);

        let vc_doc_2 = get_graph_from_ntriples_str(VC_NTRIPLES_2);
        let vc_proof_2 = get_graph_from_ntriples_str(VC_PROOF_NTRIPLES_2);
        let vc_2 = VerifiableCredential::new(vc_doc_2, vc_proof_2);

        let disclosed_vc_doc_2 = get_graph_from_ntriples_str(DISCLOSED_VC_NTRIPLES_2);
        let disclosed_vc_proof_2 = get_graph_from_ntriples_str(DISCLOSED_VC_PROOF_NTRIPLES_2);
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
            VcPairString::new(
                VC_NTRIPLES_1,
                VC_PROOF_NTRIPLES_1,
                DISCLOSED_VC_NTRIPLES_1,
                DISCLOSED_VC_PROOF_NTRIPLES_1,
            ),
            VcPairString::new(
                VC_NTRIPLES_2,
                VC_PROOF_NTRIPLES_2,
                DISCLOSED_VC_NTRIPLES_2,
                DISCLOSED_VC_PROOF_NTRIPLES_2,
            ),
        ];

        let deanon_map = get_example_deanon_map_string();

        let nonce = "abcde";

        let derived_proof = derive_proof_string(
            &mut rng,
            &vc_pairs,
            &deanon_map,
            Some(nonce),
            KEY_GRAPH_NTRIPLES,
        )
        .unwrap();
        println!("derived_proof: {}", derived_proof);

        let verified =
            verify_proof_string(&mut rng, &derived_proof, Some(nonce), KEY_GRAPH_NTRIPLES);
        assert!(verified.is_ok(), "{:?}", verified)
    }

    #[test]
    fn verify_proof_success() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed
        let key_graph: KeyGraph = get_graph_from_ntriples_str(KEY_GRAPH_NTRIPLES).into();
        let vp = get_dataset_from_nquads_str(VP_NQUADS);
        let nonce = "abcde";
        let verified = verify_proof(&mut rng, &vp, Some(nonce), &key_graph);
        assert!(verified.is_ok(), "{:?}", verified)
    }

    #[test]
    fn verify_proof_string_success() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed
        let nonce = "abcde";
        let verified = verify_proof_string(&mut rng, VP_NQUADS, Some(nonce), KEY_GRAPH_NTRIPLES);
        assert!(verified.is_ok(), "{:?}", verified)
    }

    #[test]
    fn derive_and_verify_proof_without_nonce() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed
        let key_graph: KeyGraph = get_graph_from_ntriples_str(KEY_GRAPH_NTRIPLES).into();

        let vc_doc_1 = get_graph_from_ntriples_str(VC_NTRIPLES_1);
        let vc_proof_1 = get_graph_from_ntriples_str(VC_PROOF_NTRIPLES_1);
        let vc_1 = VerifiableCredential::new(vc_doc_1, vc_proof_1);

        let disclosed_vc_doc_1 = get_graph_from_ntriples_str(DISCLOSED_VC_NTRIPLES_1);
        let disclosed_vc_proof_1 = get_graph_from_ntriples_str(DISCLOSED_VC_PROOF_NTRIPLES_1);
        let disclosed_1 = VerifiableCredential::new(disclosed_vc_doc_1, disclosed_vc_proof_1);

        let vc_doc_2 = get_graph_from_ntriples_str(VC_NTRIPLES_2);
        let vc_proof_2 = get_graph_from_ntriples_str(VC_PROOF_NTRIPLES_2);
        let vc_2 = VerifiableCredential::new(vc_doc_2, vc_proof_2);

        let disclosed_vc_doc_2 = get_graph_from_ntriples_str(DISCLOSED_VC_NTRIPLES_2);
        let disclosed_vc_proof_2 = get_graph_from_ntriples_str(DISCLOSED_VC_PROOF_NTRIPLES_2);
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
            VcPairString::new(
                VC_NTRIPLES_1,
                VC_PROOF_NTRIPLES_1,
                DISCLOSED_VC_NTRIPLES_1,
                DISCLOSED_VC_PROOF_NTRIPLES_1,
            ),
            VcPairString::new(
                VC_NTRIPLES_2,
                VC_PROOF_NTRIPLES_2,
                DISCLOSED_VC_NTRIPLES_2,
                DISCLOSED_VC_PROOF_NTRIPLES_2,
            ),
        ];

        let deanon_map = get_example_deanon_map_string();

        let nonce = None;

        let derived_proof =
            derive_proof_string(&mut rng, &vc_pairs, &deanon_map, nonce, KEY_GRAPH_NTRIPLES)
                .unwrap();

        let verified = verify_proof_string(&mut rng, &derived_proof, nonce, KEY_GRAPH_NTRIPLES);

        assert!(verified.is_ok(), "{:?}", verified)
    }

    #[test]
    fn derive_without_nonce_and_verify_proof_with_nonce() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed
        let key_graph: KeyGraph = get_graph_from_ntriples_str(KEY_GRAPH_NTRIPLES).into();

        let vc_doc_1 = get_graph_from_ntriples_str(VC_NTRIPLES_1);
        let vc_proof_1 = get_graph_from_ntriples_str(VC_PROOF_NTRIPLES_1);
        let vc_1 = VerifiableCredential::new(vc_doc_1, vc_proof_1);

        let disclosed_vc_doc_1 = get_graph_from_ntriples_str(DISCLOSED_VC_NTRIPLES_1);
        let disclosed_vc_proof_1 = get_graph_from_ntriples_str(DISCLOSED_VC_PROOF_NTRIPLES_1);
        let disclosed_1 = VerifiableCredential::new(disclosed_vc_doc_1, disclosed_vc_proof_1);

        let vc_doc_2 = get_graph_from_ntriples_str(VC_NTRIPLES_2);
        let vc_proof_2 = get_graph_from_ntriples_str(VC_PROOF_NTRIPLES_2);
        let vc_2 = VerifiableCredential::new(vc_doc_2, vc_proof_2);

        let disclosed_vc_doc_2 = get_graph_from_ntriples_str(DISCLOSED_VC_NTRIPLES_2);
        let disclosed_vc_proof_2 = get_graph_from_ntriples_str(DISCLOSED_VC_PROOF_NTRIPLES_2);
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
            VcPairString::new(
                VC_NTRIPLES_1,
                VC_PROOF_NTRIPLES_1,
                DISCLOSED_VC_NTRIPLES_1,
                DISCLOSED_VC_PROOF_NTRIPLES_1,
            ),
            VcPairString::new(
                VC_NTRIPLES_2,
                VC_PROOF_NTRIPLES_2,
                DISCLOSED_VC_NTRIPLES_2,
                DISCLOSED_VC_PROOF_NTRIPLES_2,
            ),
        ];

        let deanon_map = get_example_deanon_map_string();

        let derived_proof =
            derive_proof_string(&mut rng, &vc_pairs, &deanon_map, None, KEY_GRAPH_NTRIPLES)
                .unwrap();

        let nonce = "abcde";

        let verified =
            verify_proof_string(&mut rng, &derived_proof, Some(nonce), KEY_GRAPH_NTRIPLES);

        assert!(matches!(
            verified,
            Err(RDFProofsError::MissingChallengeInVP)
        ))
    }

    #[test]
    fn derive_with_nonce_and_verify_proof_without_nonce() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed
        let key_graph: KeyGraph = get_graph_from_ntriples_str(KEY_GRAPH_NTRIPLES).into();

        let vc_doc_1 = get_graph_from_ntriples_str(VC_NTRIPLES_1);
        let vc_proof_1 = get_graph_from_ntriples_str(VC_PROOF_NTRIPLES_1);
        let vc_1 = VerifiableCredential::new(vc_doc_1, vc_proof_1);

        let disclosed_vc_doc_1 = get_graph_from_ntriples_str(DISCLOSED_VC_NTRIPLES_1);
        let disclosed_vc_proof_1 = get_graph_from_ntriples_str(DISCLOSED_VC_PROOF_NTRIPLES_1);
        let disclosed_1 = VerifiableCredential::new(disclosed_vc_doc_1, disclosed_vc_proof_1);

        let vc_doc_2 = get_graph_from_ntriples_str(VC_NTRIPLES_2);
        let vc_proof_2 = get_graph_from_ntriples_str(VC_PROOF_NTRIPLES_2);
        let vc_2 = VerifiableCredential::new(vc_doc_2, vc_proof_2);

        let disclosed_vc_doc_2 = get_graph_from_ntriples_str(DISCLOSED_VC_NTRIPLES_2);
        let disclosed_vc_proof_2 = get_graph_from_ntriples_str(DISCLOSED_VC_PROOF_NTRIPLES_2);
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
            VcPairString::new(
                VC_NTRIPLES_1,
                VC_PROOF_NTRIPLES_1,
                DISCLOSED_VC_NTRIPLES_1,
                DISCLOSED_VC_PROOF_NTRIPLES_1,
            ),
            VcPairString::new(
                VC_NTRIPLES_2,
                VC_PROOF_NTRIPLES_2,
                DISCLOSED_VC_NTRIPLES_2,
                DISCLOSED_VC_PROOF_NTRIPLES_2,
            ),
        ];

        let deanon_map = get_example_deanon_map_string();

        let nonce = "abcde";

        let derived_proof = derive_proof_string(
            &mut rng,
            &vc_pairs,
            &deanon_map,
            Some(nonce),
            KEY_GRAPH_NTRIPLES,
        )
        .unwrap();

        let verified = verify_proof_string(&mut rng, &derived_proof, None, KEY_GRAPH_NTRIPLES);

        assert!(matches!(
            verified,
            Err(RDFProofsError::MissingChallengeInRequest)
        ))
    }

    const DISCLOSED_VC_NTRIPLES_1_WITH_HIDDEN_LITERALS: &str = r#"
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
        let key_graph: KeyGraph = get_graph_from_ntriples_str(KEY_GRAPH_NTRIPLES).into();

        let mut deanon_map = get_example_deanon_map();
        deanon_map.extend(get_example_deanon_map_with_hidden_literal());

        let vc_doc_1 = get_graph_from_ntriples_str(VC_NTRIPLES_1);
        let vc_proof_1 = get_graph_from_ntriples_str(VC_PROOF_NTRIPLES_1);
        let vc_1 = VerifiableCredential::new(vc_doc_1, vc_proof_1);

        let disclosed_vc_doc_1 =
            get_graph_from_ntriples_str(DISCLOSED_VC_NTRIPLES_1_WITH_HIDDEN_LITERALS);
        let disclosed_vc_proof_1 = get_graph_from_ntriples_str(DISCLOSED_VC_PROOF_NTRIPLES_1);
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
            VC_NTRIPLES_1,
            VC_PROOF_NTRIPLES_1,
            DISCLOSED_VC_NTRIPLES_1,
            DISCLOSED_VC_PROOF_NTRIPLES_1,
        )];

        let mut deanon_map = get_example_deanon_map_string();
        deanon_map.extend(get_example_deanon_map_string_with_hidden_literal());

        let nonce = "abcde";

        let derived_proof = derive_proof_string(
            &mut rng,
            &vc_pairs,
            &deanon_map,
            Some(nonce),
            KEY_GRAPH_NTRIPLES,
        )
        .unwrap();

        let verified =
            verify_proof_string(&mut rng, &derived_proof, Some(nonce), KEY_GRAPH_NTRIPLES);

        assert!(verified.is_ok(), "{:?}", verified)
    }

    #[test]
    fn derive_proof_failed_invalid_vc() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed
        let key_graph: KeyGraph = get_graph_from_ntriples_str(KEY_GRAPH_NTRIPLES).into();

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

        let vc_doc = get_graph_from_ntriples_str(vc_ntriples);
        let vc_proof = get_graph_from_ntriples_str(VC_PROOF_NTRIPLES_1);
        let vc = VerifiableCredential::new(vc_doc, vc_proof);

        let disclosed_vc_doc = get_graph_from_ntriples_str(DISCLOSED_VC_NTRIPLES_1);
        let disclosed_vc_proof = get_graph_from_ntriples_str(DISCLOSED_VC_PROOF_NTRIPLES_1);
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
            VC_NTRIPLES_1_MODIFIED,
            VC_PROOF_NTRIPLES_1,
            DISCLOSED_VC_NTRIPLES_1,
            DISCLOSED_VC_PROOF_NTRIPLES_1,
        )];

        let deanon_map = get_example_deanon_map_string();

        let nonce = "abcde";

        let derived_proof = derive_proof_string(
            &mut rng,
            &vc_pairs,
            &deanon_map,
            Some(nonce),
            KEY_GRAPH_NTRIPLES,
        );

        assert!(matches!(
            derived_proof,
            Err(RDFProofsError::BBSPlus(
                bbs_plus::prelude::BBSPlusError::InvalidSignature
            ))
        ))
    }
}
