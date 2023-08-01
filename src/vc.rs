use crate::context::PROOF;

use oxrdf::{dataset::GraphView, Graph, Triple};
use std::collections::{BTreeMap, HashMap};

pub struct VerifiableCredential {
    pub document: Graph,
    pub proof: Graph,
}

impl VerifiableCredential {
    pub fn new(document: Graph, proof: Graph) -> Self {
        Self { document, proof }
    }
}

pub struct VerifiableCredentialView<'a> {
    pub document: GraphView<'a>,
    pub proof: GraphView<'a>,
}

impl<'a> VerifiableCredentialView<'a> {
    pub fn new(document: GraphView<'a>, proof: GraphView<'a>) -> Self {
        Self { document, proof }
    }
}

#[derive(Clone)]
pub struct VerifiableCredentialTriples {
    pub document: Vec<Triple>,
    pub proof: Vec<Triple>,
}

impl From<VerifiableCredentialView<'_>> for VerifiableCredentialTriples {
    fn from(view: VerifiableCredentialView) -> Self {
        let mut document = view
            .document
            .iter()
            .filter(|t| t.predicate != PROOF) // filter out `proof`
            .map(|t| t.into_owned())
            .collect::<Vec<_>>();
        document.sort_by_cached_key(|t| t.to_string());
        let mut proof = view
            .proof
            .iter()
            .map(|t| t.into_owned())
            .collect::<Vec<_>>();
        proof.sort_by_cached_key(|t| t.to_string());
        Self { document, proof }
    }
}

impl From<&VerifiableCredential> for VerifiableCredentialTriples {
    fn from(view: &VerifiableCredential) -> Self {
        let mut document = view
            .document
            .iter()
            .filter(|t| t.predicate != PROOF) // filter out `proof`
            .map(|t| t.into_owned())
            .collect::<Vec<_>>();
        document.sort_by_cached_key(|t| t.to_string());
        let mut proof = view
            .proof
            .iter()
            .map(|t| t.into_owned())
            .collect::<Vec<_>>();
        proof.sort_by_cached_key(|t| t.to_string());
        Self { document, proof }
    }
}

impl From<&CanonicalVerifiableCredentialTriples> for VerifiableCredentialTriples {
    fn from(view: &CanonicalVerifiableCredentialTriples) -> Self {
        let mut document = view.document.iter().map(|t| t.clone()).collect::<Vec<_>>();
        document.sort_by_cached_key(|t| t.to_string());
        let mut proof = view.proof.iter().map(|t| t.clone()).collect::<Vec<_>>();
        proof.sort_by_cached_key(|t| t.to_string());
        Self { document, proof }
    }
}

pub struct CanonicalVerifiableCredentialTriples {
    pub document: Vec<Triple>,
    pub document_issued_identifiers_map: HashMap<String, String>,
    pub proof: Vec<Triple>,
    pub proof_issued_identifiers_map: HashMap<String, String>,
}

impl CanonicalVerifiableCredentialTriples {
    pub fn new(
        mut document: Vec<Triple>,
        document_issued_identifiers_map: HashMap<String, String>,
        mut proof: Vec<Triple>,
        proof_issued_identifiers_map: HashMap<String, String>,
    ) -> Self {
        document.sort_by_cached_key(|t| t.to_string());
        proof.sort_by_cached_key(|t| t.to_string());
        Self {
            document,
            document_issued_identifiers_map,
            proof,
            proof_issued_identifiers_map,
        }
    }
}

#[derive(Debug)]
pub struct DisclosedVerifiableCredential {
    pub document: BTreeMap<usize, Option<Triple>>,
    pub proof: BTreeMap<usize, Option<Triple>>,
}
