use crate::{
    constants::{DELIMITER, MAP_TO_SCALAR_AS_HASH_DST, NYM_IRI_PREFIX},
    context::{DATA_INTEGRITY_PROOF, FILTER, PROOF, VERIFIABLE_CREDENTIAL, VERIFICATION_METHOD},
    error::RDFProofsError,
    ordered_triple::{
        OrderedGraphNameRef, OrderedGraphViews, OrderedVerifiableCredentialGraphViews,
    },
    vc::{
        DisclosedVerifiableCredential, VerifiableCredentialTriples, VerifiableCredentialView,
        VpGraphs,
    },
    VerifiableCredential,
};
use ark_bls12_381::{Bls12_381, G1Affine};
use ark_ec::pairing::Pairing;
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use bbs_plus::{
    setup::{KeypairG2, PublicKeyG2, SecretKey, SignatureParamsG1},
    signature::SignatureG1,
};
use blake2::Blake2b512;
use multibase::Base;
use oxrdf::{
    dataset::GraphView, vocab::rdf::TYPE, BlankNode, Dataset, Graph, GraphNameRef, NamedNode,
    NamedNodeRef, QuadRef, SubjectRef, Term, TermRef, Triple,
};
use oxttl::{NQuadsParser, NTriplesParser};
use proof_system::{
    proof::Proof as ProofOrig, statement::bbs_plus::PoKBBSSignatureG1 as PoKBBSSignatureG1Stmt,
    statement::Statements as StatementsOrig, witness::PoKBBSSignatureG1 as PoKBBSSignatureG1Wit,
};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub type Fr = <Bls12_381 as Pairing>::ScalarField;
pub type Proof = ProofOrig<Bls12_381, G1Affine>;
pub type Statements = StatementsOrig<Bls12_381, <Bls12_381 as Pairing>::G1Affine>;
pub type BBSPlusHash = Blake2b512;
pub type BBSPlusParams = SignatureParamsG1<Bls12_381>;
pub type BBSPlusKeypair = KeypairG2<Bls12_381>;
pub type BBSPlusSecretKey = SecretKey<Fr>;
pub type BBSPlusPublicKey = PublicKeyG2<Bls12_381>;
pub type BBSPlusSignature = SignatureG1<Bls12_381>;
pub type PoKBBSPlusStmt<E> = PoKBBSSignatureG1Stmt<E>;
pub type PoKBBSPlusWit<E> = PoKBBSSignatureG1Wit<E>;

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename = "0")]
pub struct StatementIndexMap {
    #[serde(rename = "1")]
    document_map: Vec<usize>,
    #[serde(rename = "2")]
    document_len: usize,
    #[serde(rename = "3")]
    proof_map: Vec<usize>,
    #[serde(rename = "4")]
    proof_len: usize,
}

impl StatementIndexMap {
    pub fn new(
        document_map: Vec<usize>,
        document_len: usize,
        proof_map: Vec<usize>,
        proof_len: usize,
    ) -> Self {
        Self {
            document_map,
            document_len,
            proof_map,
            proof_len,
        }
    }
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ProofWithIndexMap {
    #[serde_as(as = "Bytes")]
    pub proof: Vec<u8>,
    pub index_map: Vec<StatementIndexMap>,
}

pub fn is_nym(node: &NamedNode) -> bool {
    node.as_str().starts_with(NYM_IRI_PREFIX)
}

pub fn hash_str_to_str(s: &str) -> String {
    multibase::encode(Base::Base64Url, Sha256::digest(s.as_bytes()))
}

pub fn canonicalize_graph(
    graph: &Graph,
) -> Result<(Graph, HashMap<String, String>), RDFProofsError> {
    let serialized_canonical_form = rdf_canon::canonicalize_graph(graph)?;
    let postfix = hash_str_to_str(&serialized_canonical_form);

    let issued_identifiers_map = &rdf_canon::issue_graph(graph)?;
    let global_issued_identifiers_map = issued_identifiers_map
        .iter()
        .map(|(k, v)| (k.clone(), format!("{}.{}", v, postfix)))
        .collect::<HashMap<_, _>>();

    let canonicalized_graph = rdf_canon::relabel_graph(graph, &global_issued_identifiers_map)?;

    Ok((canonicalized_graph, global_issued_identifiers_map))
}

pub fn get_hasher() -> DefaultFieldHasher<Blake2b512> {
    <DefaultFieldHasher<Blake2b512> as HashToField<Fr>>::new(MAP_TO_SCALAR_AS_HASH_DST)
}

pub fn hash_terms_to_field(
    terms: &Vec<Term>,
    hasher: &DefaultFieldHasher<Blake2b512>,
) -> Result<Vec<Fr>, RDFProofsError> {
    terms
        .iter()
        .map(|term| hash_term_to_field(term.as_ref(), hasher))
        .collect()
}

pub fn hash_term_to_field(
    term: TermRef,
    hasher: &DefaultFieldHasher<Blake2b512>,
) -> Result<Fr, RDFProofsError> {
    hasher
        .hash_to_field(term.to_string().as_bytes(), 1)
        .pop()
        .ok_or(RDFProofsError::HashToField)
}

pub fn get_delimiter() -> Result<Fr, RDFProofsError> {
    let hasher = get_hasher();
    hasher
        .hash_to_field(DELIMITER, 1)
        .pop()
        .ok_or(RDFProofsError::HashToField)
}

pub fn get_verification_method_identifier(
    proof_options: &Graph,
) -> Result<NamedNodeRef, RDFProofsError> {
    let proof_options_subject = proof_options
        .subject_for_predicate_object(TYPE, DATA_INTEGRITY_PROOF)
        .ok_or(RDFProofsError::InvalidProofConfiguration)?;
    let verification_method_identifier = proof_options
        .object_for_subject_predicate(proof_options_subject, VERIFICATION_METHOD)
        .ok_or(RDFProofsError::InvalidProofConfiguration)?;
    match verification_method_identifier {
        TermRef::NamedNode(v) => Ok(v),
        _ => Err(RDFProofsError::InvalidVerificationMethodURL),
    }
}

pub fn randomize_bnodes(original_graph: &Graph, disclosed_graph: &Graph) -> (Graph, Graph) {
    let mut random_map = HashMap::new();

    // randomize each blank nodes in the original graph
    let original_iter = original_graph.iter().map(|triple| {
        let s = match triple.subject {
            SubjectRef::BlankNode(b) => random_map
                .entry(b)
                .or_insert_with(|| BlankNode::default())
                .to_owned()
                .into(),
            _ => triple.subject.into_owned(),
        };
        let p = triple.predicate.into_owned();
        let o = match triple.object {
            TermRef::BlankNode(b) => random_map
                .entry(b)
                .or_insert_with(|| BlankNode::default())
                .to_owned()
                .into(),
            _ => triple.object.into_owned(),
        };
        Triple::new(s, p, o)
    });
    let randomized_original_graph = Graph::from_iter(original_iter);

    // apply the same bnode randomization to the disclosed graph
    let disclosed_iter = disclosed_graph.iter().map(|triple| {
        let s = match triple.subject {
            SubjectRef::BlankNode(b) => random_map
                .get(&b)
                .unwrap_or(&b.into_owned())
                .to_owned()
                .into(),
            _ => triple.subject.into_owned(),
        };
        let p = triple.predicate.into_owned();
        let o = match triple.object {
            TermRef::BlankNode(b) => random_map
                .get(&b)
                .unwrap_or(&b.into_owned())
                .to_owned()
                .into(),
            _ => triple.object.into_owned(),
        };
        Triple::new(s, p, o)
    });

    let randomized_disclosed_graph = Graph::from_iter(disclosed_iter);

    (randomized_original_graph, randomized_disclosed_graph)
}

pub fn decompose_vp<'a>(vp: &'a Dataset) -> Result<VpGraphs<'a>, RDFProofsError> {
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

    Ok(VpGraphs {
        metadata,
        proof: vp_proof,
        proof_graph_name: vp_proof_graph_name,
        filters,
        disclosed_vcs,
    })
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

pub fn reorder_vc_triples(
    vc_triples: &[VerifiableCredentialTriples],
    index_map: &[StatementIndexMap],
) -> Result<Vec<DisclosedVerifiableCredential>, RDFProofsError> {
    vc_triples
        .iter()
        .enumerate()
        .map(|(i, VerifiableCredentialTriples { document, proof })| {
            let StatementIndexMap {
                document_map,
                proof_map,
                document_len,
                proof_len,
            } = &index_map.get(i).ok_or(RDFProofsError::DeriveProofValue)?;

            let mut mapped_document = document
                .iter()
                .enumerate()
                .map(|(j, triple)| {
                    let mapped_index = document_map
                        .get(j)
                        .ok_or(RDFProofsError::DeriveProofValue)?;
                    Ok((*mapped_index, Some(triple.clone())))
                })
                .collect::<Result<BTreeMap<_, _>, RDFProofsError>>()?;
            for i in 0..*document_len {
                mapped_document.entry(i).or_insert(None);
            }

            let mut mapped_proof = proof
                .iter()
                .enumerate()
                .map(|(j, triple)| {
                    let mapped_index = proof_map.get(j).ok_or(RDFProofsError::DeriveProofValue)?;
                    Ok((*mapped_index, Some(triple.clone())))
                })
                .collect::<Result<BTreeMap<_, _>, RDFProofsError>>()?;
            for i in 0..*proof_len {
                mapped_proof.entry(i).or_insert(None);
            }

            Ok(DisclosedVerifiableCredential {
                document: mapped_document,
                proof: mapped_proof,
            })
        })
        .collect::<Result<Vec<_>, RDFProofsError>>()
}

pub fn get_graph_from_ntriples(ntriples: &str) -> Result<Graph, RDFProofsError> {
    let iter = NTriplesParser::new()
        .parse_read(ntriples.as_bytes())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Graph::from_iter(iter))
}

pub fn get_dataset_from_nquads(nquads: &str) -> Result<Dataset, RDFProofsError> {
    let iter = NQuadsParser::new()
        .parse_read(nquads.as_bytes())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Dataset::from_iter(iter))
}

pub fn get_vc_from_ntriples(
    document: &str,
    proof: &str,
) -> Result<VerifiableCredential, RDFProofsError> {
    let document = get_graph_from_ntriples(document)?;
    let proof = get_graph_from_ntriples(proof)?;
    Ok(VerifiableCredential::new(document, proof))
}
