use crate::{
    constants::{CRYPTOSUITE_BOUND_SIGN, CRYPTOSUITE_SIGN},
    context::{
        CRYPTOSUITE, DATA_INTEGRITY_PROOF, FILTER, MULTIBASE, PROOF, PROOF_VALUE,
        VERIFIABLE_CREDENTIAL,
    },
    error::RDFProofsError,
    ordered_triple::{
        OrderedGraphNameRef, OrderedGraphViews, OrderedVerifiableCredentialGraphViews,
    },
};
use oxrdf::{
    dataset::GraphView, vocab, Dataset, Graph, GraphNameRef, Literal, NamedNodeRef, QuadRef,
    TermRef, Triple, TripleRef,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub struct VerifiableCredential {
    pub document: Graph,
    pub proof: Graph,
}

impl VerifiableCredential {
    pub fn new(document: Graph, proof: Graph) -> Self {
        Self { document, proof }
    }

    pub fn get_cryptosuite(&self) -> Result<String, RDFProofsError> {
        let VerifiableCredential { proof, .. } = self;

        // TODO: assert there is at most one triple `* a DataIntegrity` in `proof`
        let proof_subject = proof
            .subject_for_predicate_object(vocab::rdf::TYPE, DATA_INTEGRITY_PROOF)
            .ok_or(RDFProofsError::InvalidProofConfiguration)?;

        // TODO: assert there is at most one triple `* proofValue *` in `proof`
        if let Some(proof_value) = proof.object_for_subject_predicate(proof_subject, CRYPTOSUITE) {
            match proof_value {
                TermRef::Literal(v) => Ok(v.value().to_string()),
                _ => Err(RDFProofsError::VCWithoutCryptosuite),
            }
        } else {
            Err(RDFProofsError::VCWithoutCryptosuite)
        }
    }

    pub fn is_bound(&self) -> Result<bool, RDFProofsError> {
        match self.get_cryptosuite()?.as_str() {
            CRYPTOSUITE_BOUND_SIGN => Ok(true),
            CRYPTOSUITE_SIGN => Ok(false),
            _ => Err(RDFProofsError::VCWithUnsupportedCryptosuite),
        }
    }

    pub fn add_proof_value(self: &mut Self, proof_value: String) -> Result<(), RDFProofsError> {
        let VerifiableCredential { proof, .. } = self;

        // TODO: assert there is at most one triple `* a DataIntegrity` in `proof`
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

    pub fn replace_proof_value(self: &mut Self, proof_value: String) -> Result<(), RDFProofsError> {
        let VerifiableCredential { proof, .. } = self;

        let proof_subject = proof
            .subject_for_predicate_object(vocab::rdf::TYPE, DATA_INTEGRITY_PROOF)
            .ok_or(RDFProofsError::InvalidProofConfiguration)?
            .into_owned();
        let existing_proof_value = proof
            .object_for_subject_predicate(&proof_subject, PROOF_VALUE)
            .ok_or(RDFProofsError::VCWithoutProofValue)?
            .into_owned();
        proof.insert(TripleRef::new(
            &proof_subject,
            PROOF_VALUE,
            &Literal::new_typed_literal(proof_value, MULTIBASE),
        ));
        proof.remove(TripleRef::new(
            &proof_subject,
            PROOF_VALUE,
            &existing_proof_value,
        ));
        Ok(())
    }

    pub fn get_proof_value(self: &Self) -> Result<String, RDFProofsError> {
        let VerifiableCredential { proof, .. } = self;

        // TODO: assert there is at most one triple `* a DataIntegrity` in `proof`
        let proof_subject = proof
            .subject_for_predicate_object(vocab::rdf::TYPE, DATA_INTEGRITY_PROOF)
            .ok_or(RDFProofsError::InvalidProofConfiguration)?;

        // TODO: assert there is at most one triple `* proofValue *` in `proof`
        if let Some(proof_value) = proof.object_for_subject_predicate(proof_subject, PROOF_VALUE) {
            match proof_value {
                TermRef::Literal(v) => Ok(v.value().to_string()),
                _ => Err(RDFProofsError::VCWithInvalidProofValue),
            }
        } else {
            Err(RDFProofsError::VCWithoutProofValue)
        }
    }

    pub fn get_proof_config(self: &Self) -> Graph {
        Graph::from_iter(
            self.proof
                .iter()
                .filter(|t| t.predicate != PROOF_VALUE)
                .collect::<Vec<_>>(),
        )
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
    pub fn get_cryptosuite(&self) -> Result<String, RDFProofsError> {
        let VerifiableCredentialView { proof, .. } = self;

        // TODO: assert there is at most one triple `* a DataIntegrity` in `proof`
        let proof_subject = proof
            .subject_for_predicate_object(vocab::rdf::TYPE, DATA_INTEGRITY_PROOF)
            .ok_or(RDFProofsError::InvalidProofConfiguration)?;

        // TODO: assert there is at most one triple `* proofValue *` in `proof`
        if let Some(proof_value) = proof.object_for_subject_predicate(proof_subject, CRYPTOSUITE) {
            match proof_value {
                TermRef::Literal(v) => Ok(v.value().to_string()),
                _ => Err(RDFProofsError::VCWithoutCryptosuite),
            }
        } else {
            Err(RDFProofsError::VCWithoutCryptosuite)
        }
    }

    pub fn is_bound(&self) -> Result<bool, RDFProofsError> {
        match self.get_cryptosuite()?.as_str() {
            CRYPTOSUITE_BOUND_SIGN => Ok(true),
            CRYPTOSUITE_SIGN => Ok(false),
            _ => Err(RDFProofsError::VCWithUnsupportedCryptosuite),
        }
    }
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

pub struct VerifiablePresentation<'a> {
    pub metadata: GraphView<'a>,
    pub proof: GraphView<'a>,
    pub proof_graph_name: GraphNameRef<'a>,
    pub filters: OrderedGraphViews<'a>,
    pub disclosed_vcs: OrderedVerifiableCredentialGraphViews<'a>,
}

impl<'a> TryFrom<&'a Dataset> for VerifiablePresentation<'a> {
    type Error = RDFProofsError;

    fn try_from(vp: &'a Dataset) -> Result<VerifiablePresentation<'a>, RDFProofsError> {
        let mut vp_graphs = dataset_into_ordered_graphs(vp);

        // extract VP metadata (default graph)
        let metadata = vp_graphs
            .remove(&OrderedGraphNameRef::new(GraphNameRef::default()))
            .ok_or(RDFProofsError::Other(
                "VP graphs must have default graph".to_owned(),
            ))?;

        // extract VP proof graph
        let (vp_proof_graph_name, vp_proof) = remove_graph(&mut vp_graphs, &metadata, PROOF)?;

        // extract filter graphs if any
        let filters = remove_graphs(&mut vp_graphs, &vp_proof, FILTER)?;

        // extract VC graphs
        let vcs = remove_graphs(&mut vp_graphs, &metadata, VERIFIABLE_CREDENTIAL)?;

        // extract VC proof graphs
        let disclosed_vcs = vcs
            .into_iter()
            .map(|(vc_graph_name, vc)| {
                let (_, vc_proof) = remove_graph(&mut vp_graphs, &vc, PROOF)?;
                Ok((vc_graph_name, VerifiableCredentialView::new(vc, vc_proof)))
            })
            .collect::<Result<OrderedVerifiableCredentialGraphViews, RDFProofsError>>()?;

        // check if `vp_graphs` is empty
        if !vp_graphs.is_empty() {
            return Err(RDFProofsError::InvalidVP);
        }

        Ok(VerifiablePresentation {
            metadata,
            proof: vp_proof,
            proof_graph_name: vp_proof_graph_name.into(),
            filters,
            disclosed_vcs,
        })
    }
}

impl<'a> VerifiablePresentation<'a> {
    pub fn get_proof_value(self: &Self) -> Result<String, RDFProofsError> {
        let VerifiablePresentation { proof, .. } = self;

        // TODO: assert there is at most one triple `* a DataIntegrity` in `proof`
        let proof_subject = proof
            .subject_for_predicate_object(vocab::rdf::TYPE, DATA_INTEGRITY_PROOF)
            .ok_or(RDFProofsError::InvalidVP)?;

        // TODO: assert there is at most one triple `* proofValue *` in `proof`
        if let Some(proof_value) = proof.object_for_subject_predicate(proof_subject, PROOF_VALUE) {
            match proof_value {
                TermRef::Literal(v) => Ok(v.value().to_string()),
                _ => Err(RDFProofsError::VCWithInvalidProofValue),
            }
        } else {
            Err(RDFProofsError::VCWithoutProofValue)
        }
    }

    pub fn get_proof_config_literal(
        self: &Self,
        predicate: NamedNodeRef,
    ) -> Result<Option<String>, RDFProofsError> {
        let VerifiablePresentation { proof, .. } = self;

        // TODO: assert there is at most one triple `* a DataIntegrity` in `proof`
        let proof_subject = proof
            .subject_for_predicate_object(vocab::rdf::TYPE, DATA_INTEGRITY_PROOF)
            .ok_or(RDFProofsError::InvalidVP)?;

        // TODO: assert there is at most one triple `* predicate *` in `proof`
        if let Some(config) = proof.object_for_subject_predicate(proof_subject, predicate) {
            match config {
                TermRef::Literal(v) => Ok(Some(v.value().to_string())),
                _ => Err(RDFProofsError::MissingProofConfigLiteral(predicate.into())),
            }
        } else {
            Ok(None)
        }
    }
}

fn dataset_into_ordered_graphs(dataset: &Dataset) -> OrderedGraphViews {
    let graph_name_set = dataset
        .iter()
        .map(|QuadRef { graph_name, .. }| OrderedGraphNameRef::new(graph_name))
        .collect::<BTreeSet<_>>();

    graph_name_set
        .into_iter()
        .map(|graph_name| (graph_name.clone(), dataset.graph(graph_name)))
        .collect()
}

// function to remove from the VP the multiple graphs that are reachable from `source` via `link`
fn remove_graphs<'a>(
    vp_graphs: &mut OrderedGraphViews<'a>,
    source: &GraphView<'a>,
    link: NamedNodeRef,
) -> Result<OrderedGraphViews<'a>, RDFProofsError> {
    source
        .iter()
        .filter(|triple| triple.predicate == link)
        .map(|triple| {
            Ok((
                triple.object.try_into()?,
                vp_graphs
                    .remove(&triple.object.try_into()?)
                    .ok_or(RDFProofsError::InvalidVP)?,
            ))
        })
        .collect::<Result<OrderedGraphViews, RDFProofsError>>()
}

// function to remove from the VP the single graph that is reachable from `source` via `link`
fn remove_graph<'a>(
    vp_graphs: &mut OrderedGraphViews<'a>,
    source: &GraphView<'a>,
    link: NamedNodeRef,
) -> Result<(OrderedGraphNameRef<'a>, GraphView<'a>), RDFProofsError> {
    let mut graphs = remove_graphs(vp_graphs, source, link)?;
    match graphs.pop_first() {
        Some((graph_name, graph)) => {
            if graphs.is_empty() {
                Ok((graph_name, graph))
            } else {
                Err(RDFProofsError::InvalidVP)
            }
        }
        None => Err(RDFProofsError::InvalidVP),
    }
}
