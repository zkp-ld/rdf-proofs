use crate::{error::SignError, vc::VerifiableCredential};
use oxrdf::{Graph, Term};
use rdf_canon::{issue_graph, relabel_graph, sort_graph};

pub fn sign(
    unsecured_credential: &VerifiableCredential,
) -> Result<VerifiableCredential, SignError> {
    let VerifiableCredential { document, proof } = unsecured_credential;
    let transformed_document = transform(document)?;
    let canonical_proof_config = configure_proof(proof)?;
    let hash_data = hash(transformed_document, canonical_proof_config);
    let proof_value = serialize_proof(hash_data, proof);
    Ok(add_proof_value(unsecured_credential, proof_value))
}

fn transform(unsecured_document: &Graph) -> Result<Vec<Term>, SignError> {
    let issued_identifiers_map = &issue_graph(unsecured_document)?;
    let canonicalized_graph = relabel_graph(unsecured_document, issued_identifiers_map)?;
    let canonicalized_triples = sort_graph(&canonicalized_graph);
    Ok(canonicalized_triples
        .into_iter()
        .flat_map(|t| vec![t.subject.into(), t.predicate.into(), t.object])
        .collect())
}

fn configure_proof(proof_options: &Graph) -> Result<Vec<Term>, SignError> {
    // TODO: validate options

    transform(proof_options)
}

fn hash(transformed_document: Vec<Term>, canonical_proof_config: Vec<Term>) -> Vec<String> {
    todo!();
}

fn serialize_proof(hash_data: Vec<String>, proof_options: &Graph) -> String {
    todo!();
}

fn add_proof_value(
    unsecured_credential: &VerifiableCredential,
    proof_value: String,
) -> VerifiableCredential {
    todo!();
}

#[cfg(test)]
mod tests {
    use super::transform;
    use oxrdf::Graph;
    use oxttl::NTriplesParser;
    use std::io::Cursor;

    #[test]
    fn transform_simple() -> () {
        let unsecured_document_ntriples = r#"
_:e0 <https://www.w3.org/2018/credentials#expirationDate> "2023-12-31T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:e0 <https://www.w3.org/2018/credentials#issuanceDate> "2020-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:e0 <https://www.w3.org/2018/credentials#credentialSubject> <http://example.org/vaccine/a> .
_:e0 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer3> .
_:e0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/vaccine/a> <http://schema.org/name> "AwesomeVaccine" .
<http://example.org/vaccine/a> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccine> .
<http://example.org/vaccine/a> <http://schema.org/status> "active" .
<http://example.org/vaccine/a> <http://schema.org/manufacturer> <http://example.org/awesomeCompany> .
"#;
        let unsecured_document = Graph::from_iter(
            NTriplesParser::new()
                .parse_from_read(Cursor::new(unsecured_document_ntriples))
                .into_iter()
                .map(|x| x.unwrap()),
        );
        let transformed_document = transform(&unsecured_document);
    }
}
