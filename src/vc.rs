use crate::{
    context::{DATA_INTEGRITY_PROOF, MULTIBASE, PROOF, PROOF_VALUE},
    error::RDFProofsError,
    ordered_triple::{
        OrderedGraphNameRef, OrderedGraphViews, OrderedVerifiableCredentialGraphViews,
    },
};
use oxrdf::{dataset::GraphView, vocab, Graph, Literal, Triple};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct VerifiableCredential {
    pub document: Graph,
    pub proof: Graph,
}

impl VerifiableCredential {
    pub fn new(document: Graph, proof: Graph) -> Self {
        Self { document, proof }
    }

    pub fn add_proof_value(self: &mut Self, proof_value: String) -> Result<(), RDFProofsError> {
        let VerifiableCredential { proof, .. } = self;
        let proof_subject = proof
            .subject_for_predicate_object(vocab::rdf::TYPE, DATA_INTEGRITY_PROOF)
            .ok_or(RDFProofsError::InvalidProofConfiguration)?;
        proof.insert(&Triple::new(
            proof_subject,
            PROOF_VALUE,
            Literal::new_typed_literal(proof_value, MULTIBASE),
        ));
        Ok(())
    }
}

impl std::fmt::Display for VerifiableCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "document:")?;
        for t in self.document.iter() {
            writeln!(f, "{} .", t.to_string())?;
        }
        writeln!(f, "proof:")?;
        for t in self.proof.iter() {
            writeln!(f, "{} .", t.to_string())?;
        }
        Ok(())
    }
}

#[derive(Clone)]
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

impl From<&VerifiableCredentialView<'_>> for VerifiableCredentialTriples {
    fn from(view: &VerifiableCredentialView) -> Self {
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

#[derive(Debug)]
pub struct DisclosedVerifiableCredential {
    pub document: BTreeMap<usize, Option<Triple>>,
    pub proof: BTreeMap<usize, Option<Triple>>,
}

pub struct VcPair {
    pub original: VerifiableCredential,
    pub disclosed: VerifiableCredential,
}

impl VcPair {
    pub fn new(original: VerifiableCredential, disclosed: VerifiableCredential) -> Self {
        Self {
            original,
            disclosed,
        }
    }

    pub fn to_string(&self) -> String {
        format!(
            "vc:\n{}vc_proof:\n{}\ndisclosed_vc:\n{}disclosed_vc_proof:\n{}\n",
            &self
                .original
                .document
                .iter()
                .map(|q| format!("{} .\n", q.to_string()))
                .collect::<String>(),
            &self
                .original
                .proof
                .iter()
                .map(|q| format!("{} .\n", q.to_string()))
                .collect::<String>(),
            &self
                .disclosed
                .document
                .iter()
                .map(|q| format!("{} .\n", q.to_string()))
                .collect::<String>(),
            &self
                .disclosed
                .proof
                .iter()
                .map(|q| format!("{} .\n", q.to_string()))
                .collect::<String>()
        )
    }
}

pub struct VcPairString {
    pub original_document: String,
    pub original_proof: String,
    pub disclosed_document: String,
    pub disclosed_proof: String,
}

impl VcPairString {
    pub fn new(
        original_document: &str,
        original_proof: &str,
        disclosed_document: &str,
        disclosed_proof: &str,
    ) -> Self {
        Self {
            original_document: original_document.to_string(),
            original_proof: original_proof.to_string(),
            disclosed_document: disclosed_document.to_string(),
            disclosed_proof: disclosed_proof.to_string(),
        }
    }
}

pub struct VpGraphs<'a> {
    pub metadata: GraphView<'a>,
    pub proof: GraphView<'a>,
    pub proof_graph_name: OrderedGraphNameRef<'a>,
    pub filters: OrderedGraphViews<'a>,
    pub disclosed_vcs: OrderedVerifiableCredentialGraphViews<'a>,
}
