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
    _:b0 <https://w3id.org/security#proofValue> "utEnCefxSJlHuHFWGuCEqapeOkbNUMcUZfixkTP-eelRRXBCUpSl8wNNxHQqDcVgDnHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
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
    _:b0 <https://w3id.org/security#proofValue> "utEnCefxSJlHuHFWGuCEqapeOkbNUMcUZfixkTP-eelRRXBCUpSl8wNNxHQqDcVgDnHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
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
    _:b0 <https://w3id.org/security#proofValue> "usjQI4FuaD8udL2e5Rhvf4J4L0IOjmXT7Q3E40FXnIG-GQ6GMJkUuLv5tU1gJjW42nHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
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
    _:c14n10 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:c14n8 .
    _:c14n10 <https://w3id.org/security#proof> _:c14n0 _:c14n8 .
    _:c14n10 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n5 _:c14n8 .
    _:c14n10 <https://www.w3.org/2018/credentials#expirationDate> "2023-12-31T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n8 .
    _:c14n10 <https://www.w3.org/2018/credentials#issuanceDate> "2020-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n8 .
    _:c14n10 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer3> _:c14n8 .
    _:c14n11 <http://example.org/vocab/vaccine> _:c14n5 _:c14n6 .
    _:c14n11 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> _:c14n6 .
    _:c14n13 <http://example.org/vocab/isPatientOf> _:c14n11 _:c14n6 .
    _:c14n13 <http://schema.org/worksFor> _:c14n9 _:c14n6 .
    _:c14n13 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> _:c14n6 .
    _:c14n14 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:c14n6 .
    _:c14n14 <https://w3id.org/security#proof> _:c14n12 _:c14n6 .
    _:c14n14 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n13 _:c14n6 .
    _:c14n14 <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n6 .
    _:c14n14 <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n6 .
    _:c14n14 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> _:c14n6 .
    _:c14n2 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n12 .
    _:c14n2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n12 .
    _:c14n2 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" _:c14n12 .
    _:c14n2 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n12 .
    _:c14n2 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> _:c14n12 .
    _:c14n3 <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n0 .
    _:c14n3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n0 .
    _:c14n3 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" _:c14n0 .
    _:c14n3 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n0 .
    _:c14n3 <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> _:c14n0 .
    _:c14n4 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiablePresentation> .
    _:c14n4 <https://w3id.org/security#proof> _:c14n1 .
    _:c14n4 <https://www.w3.org/2018/credentials#verifiableCredential> _:c14n6 .
    _:c14n4 <https://www.w3.org/2018/credentials#verifiableCredential> _:c14n8 .
    _:c14n5 <http://schema.org/status> "active" _:c14n8 .
    _:c14n5 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccine> _:c14n8 .
    _:c14n7 <http://purl.org/dc/terms/created> "2023-08-23T09:49:27.042628313Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n1 .
    _:c14n7 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n1 .
    _:c14n7 <https://w3id.org/security#challenge> "abcde" _:c14n1 .
    _:c14n7 <https://w3id.org/security#cryptosuite> "bbs-termwise-proof-2023" _:c14n1 .
    _:c14n7 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n1 .
    _:c14n7 <https://w3id.org/security#proofValue> "uomVwcm9vZlkJ2gIAAAAAAAAAAKzAMv_PeFt9Aa3flTPd1SLsP6q0CsKszGN6L-Pn9cUXWJEm9SnYMjLcbUBKEvsnyqrOUXkOMid0Rxhxt09lQ0EeKMYQ9B15WyRyrFNjLdXct0nFiUno1Gl7cvmLR2PsvbjgF5qGnIHo1dcEmt5DUstWhVttwiYEPhLd8PIXYuAX9_D4KdIZQJn-SO3ESmcKroyImV-fCl9jT9VwRdPGrwz8_TGHsOGiUj2yX280cQFxsWhvcWfqDsCJEpyY-DdGvAIAAAAAAAAABkifYGBaVC0RtOFx1dXHd3mJizuvJuyv9a_-yZZ10Ch_1LfpwWwf_DLrRCOapWb2rlXbmrM08S2tjkJGvQplXKhgApodpupydse450Bp9oLQvGPSMbOLQCycbp6ojrVa3tK7SfEWLknTYQfR7_bE3SUAAAAAAAAAXBhS-ZXH-gb9S0poaMtbr5ez6-i0wdCFxZOOdC3bDCBszdqvtGcbjYD0mXiEQVJ4jWYVc-2Rcc6sIPx718fRF98zr3Ta_Fnq_kdkEHK6E7wUlKrTx_5u22QzdhKxyodo9ctLnPi-qNrQc_PhZueFzcZDJMZpwvvfQxL3dDG8l3Kc4v48SU8vtQr2kSrta-Hkb_4Xk4Wkn1nIOc4FSn6hbJZCrclXzox5rl9qqdH_4yZAd1SODBStM6ebEHmRfXdZSihmTvN2-cavLJjLvbSeE40Ok0xSEtkA5_RHZ-w02DnfM6902vxZ6v5HZBByuhO8FJSq08f-bttkM3YSscqHaA3ldJN0wWyyAGJrztJebzCkzSybILeBbm4FBduSZR4c3zOvdNr8Wer-R2QQcroTvBSUqtPH_m7bZDN2ErHKh2gVLUGZFdiMTHNz45Y59P_WR-JMbj4o6ZK_lqiCbGUwURUtQZkV2IxMc3Pjljn0_9ZH4kxuPijpkr-WqIJsZTBR3zOvdNr8Wer-R2QQcroTvBSUqtPH_m7bZDN2ErHKh2gVLUGZFdiMTHNz45Y59P_WR-JMbj4o6ZK_lqiCbGUwURUtQZkV2IxMc3Pjljn0_9ZH4kxuPijpkr-WqIJsZTBRFS1BmRXYjExzc-OWOfT_1kfiTG4-KOmSv5aogmxlMFFiuaDYNX3CKLDe7k_UwZmFatNR8ma6GxvBD8mRWNgSDNtegJsjza79VOCdDKOK7elaEl45bRhuM_Pz3911jB8N32uOSbOZdxw34go421llrfaYmDQWxXiLUsY-rKE9vDAN5XSTdMFssgBia87SXm8wpM0smyC3gW5uBQXbkmUeHA-KyOa0KpeW9RgkX5WfKqp0CJ70Tf3CjdnZDnCWNg1f_DmxJ0beJrwvv2YV9i3sN23owq5HBPWV-lNNJYEC7QEYKYxN3xA9bR8wSLuFOvIbYgestpaVtBRAUpgsIBacN6ZX1T0YyNtCoiM24GXz5uEeC8UsBN_cFFoRRvPLk1BWXAbV1j3vZnqzluCf0JhdgwhJGxtOH4KWWH_pSLhDil5X0yjWR-C8dM-DpCqxHznFDbqcCe_ayvBzZceqpMbHVPXLS5z4vqja0HPz4Wbnhc3GQyTGacL730MS93QxvJdyPAkhAk9p_GdU9o803LITA9it0mgS4ujY0ylzZgcx7XDsjxTBYQB30jJDXzSWjw_oBQxMUVzsXBooL1Z1MVQlI6uJZ48F7INKq0XJaMmp5-WfnOm7bg5Ay8i59VCgpDcnqJOb_I8en46a4OajZrG3roVvn8BkofwDRDDQ99dZeEH1y0uc-L6o2tBz8-Fm54XNxkMkxmnC-99DEvd0MbyXcgSZIa3DuN9SHQO2LIKvPOGcNSxDoVSbB10i7ZGrDSdxBJkhrcO431IdA7Ysgq884Zw1LEOhVJsHXSLtkasNJ3EEmSGtw7jfUh0DtiyCrzzhnDUsQ6FUmwddIu2Rqw0ncQSZIa3DuN9SHQO2LIKvPOGcNSxDoVSbB10i7ZGrDSdxBJkhrcO431IdA7Ysgq884Zw1LEOhVJsHXSLtkasNJ3EAkqVPorahvaHWiU0sYPk36xNLLIGG1EviZhUu7gVlc5-4OBf_ViPcXiCUec-0xy3glG5UEulMZ5sFDXcto_mmsNqF27M4mRJgfisNLAL2XEfIieWuf5NNUtpgptm3nqhGqeF5PpEWAXjlxsnwurNlN4e37y3-nZX1azoPYFcdMQWtpQUo_qqQDJf4MkKTLlqSo0no6jPrD3Gy0gOLhXKvzj1USsWKmcauSvtpuJQAEypb90dPb_gZILxQXXwIqLiqAgAAAAAAAABci3H30acfLSfhCa2uJAeB2FJzVNqPdZTQ6JI2qRW3FkJvysrMluxWbJuZncKyKJZTwnhFYMsNihEjAbziWMUPphwG8YRd2AXhdXWJvsmu91msyMBjYOFN-HNPWOse2sVtHGN5uf3Ahpwa4NXNM5KFFQAAAAAAAADEcNweAUR1phZnLjkXYbcWVEukPRfflr9nFjBQBLb0OTPAiisb7QGNmvXWGNF1Vrrtrh6AufP2GWC7yuqP_ChtlrNEZbr0F1xgJ3DCd4NtyX7d0HWANn_Bl1WP7hGVHlrGuO6jIDyNJoMvhJHiJ5r5h_eAWu753MXH6gHlTkqPBn_DMEtqCFJpxos8rRBTU2T9a0lTim8DLhRScruZIpEBi89kKUUh1d6yyHV9DSo14-68NcYy-EgHROYC9_1Gzy8IsyysmPnudpm-ob3XxWUee0q9GBf7JymiZtVt9us2D2qvD-7s8SQoGQnixHzqRESHECSl0K2lqB2QZeVHqnsfPAkhAk9p_GdU9o803LITA9it0mgS4ujY0ylzZgcx7XA8CSECT2n8Z1T2jzTcshMD2K3SaBLi6NjTKXNmBzHtcDTnccz0G4pf-l5hhVhObJ42Mb_QNQi-v11FbXagczBCNOdxzPQbil_6XmGFWE5snjYxv9A1CL6_XUVtdqBzMEI8CSECT2n8Z1T2jzTcshMD2K3SaBLi6NjTKXNmBzHtcDTnccz0G4pf-l5hhVhObJ42Mb_QNQi-v11FbXagczBCNOdxzPQbil_6XmGFWE5snjYxv9A1CL6_XUVtdqBzMEI053HM9BuKX_peYYVYTmyeNjG_0DUIvr9dRW12oHMwQjStMmUb2jK339-3ibBZkNGGxYXUrlcxnFkeoZvV0phNNK0yZRvaMrff37eJsFmQ0YbFhdSuVzGcWR6hm9XSmE00rTJlG9oyt9_ft4mwWZDRhsWF1K5XMZxZHqGb1dKYTTStMmUb2jK339-3ibBZkNGGxYXUrlcxnFkeoZvV0phNNK0yZRvaMrff37eJsFmQ0YbFhdSuVzGcWR6hm9XSmE0BBQAAAAAAAABhYmNkZQAAaWluZGV4X21hcIKkYTGLDQ8AAgMEBQYHCAphMhBhM4UAAQIDBGE0BaRhMYcEBQYHCAIDYTIJYTOFAAECAwRhNAU"^^<https://w3id.org/security#multibase> _:c14n1 .
    _:c14n9 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Organization> _:c14n6 .
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
