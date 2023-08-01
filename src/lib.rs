pub mod context;
pub mod error;
pub mod prover;

const CRYPTOSUITE_FOR_VP: &str = "bbs-term-proof-2023";
const NYM_IRI_PREFIX: &str = "urn:nym:";

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, io::Cursor};

    use oxrdf::{BlankNode, Graph, NamedNode};
    use oxttl::NTriplesParser;

    use crate::{
        error::DeriveProofError,
        prover::{derive_proof, VcWithDisclosed, VerifiableCredential},
    };

    #[test]
    fn derive_proof_simple() -> Result<(), DeriveProofError> {
        let vc_ntriples = r#"
<http://example.org/vicred/a> <https://www.w3.org/2018/credentials#expirationDate> "2023-12-31T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/vicred/a> <https://www.w3.org/2018/credentials#issuanceDate> "2020-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/vicred/a> <https://www.w3.org/2018/credentials#credentialSubject> <http://example.org/vaccine/a> .
<http://example.org/vicred/a> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer3> .
<http://example.org/vicred/a> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/vaccine/a> <http://schema.org/name> "AwesomeVaccine" .
<http://example.org/vaccine/a> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccine> .
<http://example.org/vaccine/a> <http://schema.org/status> "active" .
<http://example.org/vaccine/a> <http://schema.org/manufacturer> <http://example.org/awesomeCompany> .
"#;
        let vc_proof_ntriples = r#"
_:e92155627f791bae2e99100af704bd50 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:e92155627f791bae2e99100af704bd50 <https://w3id.org/security#proofValue> "PROOF_VALUE_3" .
_:e92155627f791bae2e99100af704bd50 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:e92155627f791bae2e99100af704bd50 <https://w3id.org/security#verificationMethod> <did:example:issuer3#bbs-bls-key1> .
_:e92155627f791bae2e99100af704bd50 <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:e92155627f791bae2e99100af704bd50 <https://w3id.org/security#cryptosuite> "bbs-term-sig-2023" .
"#;
        let disclosed_vc_ntriples = r#"
_:d90b9c541e44f45e2dfba4e4bc43b647 <http://schema.org/status> "active" .
_:b9044864104fc5b13cc00330049fe52a <https://www.w3.org/2018/credentials#credentialSubject> _:d90b9c541e44f45e2dfba4e4bc43b647 .
_:b9044864104fc5b13cc00330049fe52a <https://www.w3.org/2018/credentials#issuanceDate> "2020-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:b9044864104fc5b13cc00330049fe52a <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
_:b9044864104fc5b13cc00330049fe52a <https://www.w3.org/2018/credentials#expirationDate> "2023-12-31T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:b9044864104fc5b13cc00330049fe52a <https://www.w3.org/2018/credentials#issuer> <did:example:issuer3> .
"#;
        let disclosed_vc_proof_ntriples = r#"
_:e92155627f791bae2e99100af704bd50 <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:e92155627f791bae2e99100af704bd50 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:e92155627f791bae2e99100af704bd50 <https://w3id.org/security#proofValue> "PROOF_VALUE_3" .
_:e92155627f791bae2e99100af704bd50 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:e92155627f791bae2e99100af704bd50 <https://w3id.org/security#cryptosuite> "bbs-term-sig-2023" .
_:e92155627f791bae2e99100af704bd50 <https://w3id.org/security#verificationMethod> <did:example:issuer3#bbs-bls-key1> .
"#;
        let vc_doc = Graph::from_iter(
            NTriplesParser::new()
                .parse_from_read(Cursor::new(vc_ntriples))
                .into_iter()
                .map(|x| x.unwrap()),
        );
        let proof = Graph::from_iter(
            NTriplesParser::new()
                .parse_from_read(Cursor::new(vc_proof_ntriples))
                .into_iter()
                .map(|x| x.unwrap()),
        );
        let vc = VerifiableCredential::new(vc_doc, proof);

        let disclosed_vc_doc = Graph::from_iter(
            NTriplesParser::new()
                .parse_from_read(Cursor::new(disclosed_vc_ntriples))
                .into_iter()
                .map(|x| x.unwrap()),
        );
        let disclosed_vc_proof = Graph::from_iter(
            NTriplesParser::new()
                .parse_from_read(Cursor::new(disclosed_vc_proof_ntriples))
                .into_iter()
                .map(|x| x.unwrap()),
        );
        let disclosed = VerifiableCredential::new(disclosed_vc_doc, disclosed_vc_proof);

        let mut deanon_map = HashMap::new();
        deanon_map.insert(
            BlankNode::new_unchecked("d90b9c541e44f45e2dfba4e4bc43b647").into(),
            NamedNode::new_unchecked("http://example.org/vaccine/a").into(),
        );
        deanon_map.insert(
            BlankNode::new_unchecked("b9044864104fc5b13cc00330049fe52a").into(),
            NamedNode::new_unchecked("http://example.org/vicred/a").into(),
        );

        let vc_with_disclosed = VcWithDisclosed::new(vc, disclosed);
        let vcs = vec![vc_with_disclosed];
        let derived_proof = derive_proof(&vcs, &deanon_map)?;

        Ok(())
    }
}
