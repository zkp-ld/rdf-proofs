use super::constants::{CRYPTOSUITE_PROOF, NYM_IRI_PREFIX};
use crate::{
    common::{get_delimiter, get_hasher, hash_term_to_field},
    context::{
        ASSERTION_METHOD, CREATED, CRYPTOSUITE, DATA_INTEGRITY_PROOF, FILTER, PROOF, PROOF_PURPOSE,
        PROOF_VALUE, VERIFIABLE_CREDENTIAL, VERIFIABLE_CREDENTIAL_TYPE,
        VERIFIABLE_PRESENTATION_TYPE, VERIFICATION_METHOD,
    },
    error::RDFProofsError,
    keygen::generate_params,
    loader::DocumentLoader,
    vc::{
        CanonicalVerifiableCredentialTriples, DisclosedVerifiableCredential, VerifiableCredential,
        VerifiableCredentialTriples, VerifiableCredentialView,
    },
    Fr,
};
use ark_bls12_381::Bls12_381;
use ark_std::rand::RngCore;
use bbs_plus::setup::PublicKeyG2 as BBSPublicKeyG2;
use chrono::offset::Utc;
use oxrdf::{
    dataset::GraphView,
    vocab::{rdf::TYPE, xsd},
    BlankNode, Dataset, Graph, GraphNameRef, LiteralRef, NamedNode, NamedNodeRef, NamedOrBlankNode,
    NamedOrBlankNodeRef, Quad, QuadRef, Subject, Term, TermRef, Triple,
};
use proof_system::{
    statement::bbs_plus::PoKBBSSignatureG1 as PoKBBSSignatureG1Stmt,
    witness::PoKBBSSignatureG1 as PoKBBSSignatureG1Wit,
};
use rdf_canon::{issue, issue_graph, relabel, relabel_graph, serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub struct VcWithDisclosed {
    vc: VerifiableCredential,
    disclosed: VerifiableCredential,
}

impl VcWithDisclosed {
    pub fn new(vc: VerifiableCredential, disclosed: VerifiableCredential) -> Self {
        Self { vc, disclosed }
    }

    pub fn to_string(&self) -> String {
        format!(
            "vc:\n{}vc_proof:\n{}\ndisclosed_vc:\n{}disclosed_vc_proof:\n{}\n",
            &self
                .vc
                .document
                .iter()
                .map(|q| format!("{} .\n", q.to_string()))
                .collect::<String>(),
            &self
                .vc
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

struct VpGraphs<'a> {
    metadata: GraphView<'a>,
    proof: GraphView<'a>,
    filters: OrderedGraphViews<'a>,
    disclosed_vcs: OrderedVerifiableCredentialGraphViews<'a>,
}

/// `oxrdf::triple::GraphNameRef` with string-based ordering
#[derive(Eq, PartialEq, Clone)]
struct OrderedGraphNameRef<'a>(GraphNameRef<'a>);
impl Ord for OrderedGraphNameRef<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.to_string().cmp(&other.0.to_string())
    }
}
impl PartialOrd for OrderedGraphNameRef<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.to_string().partial_cmp(&other.0.to_string())
    }
}
impl<'a> From<OrderedGraphNameRef<'a>> for GraphNameRef<'a> {
    fn from(value: OrderedGraphNameRef<'a>) -> Self {
        value.0
    }
}
impl<'a> From<&'a OrderedGraphNameRef<'a>> for &'a GraphNameRef<'a> {
    fn from(value: &'a OrderedGraphNameRef<'a>) -> Self {
        &value.0
    }
}
impl<'a> TryFrom<TermRef<'a>> for OrderedGraphNameRef<'a> {
    type Error = RDFProofsError;

    fn try_from(value: TermRef<'a>) -> Result<Self, Self::Error> {
        match value {
            TermRef::NamedNode(n) => Ok(Self(n.into())),
            TermRef::BlankNode(n) => Ok(Self(n.into())),
            _ => Err(RDFProofsError::Other(
                "invalid graph name: graph name must not be literal or triple".to_string(),
            )),
        }
    }
}
impl std::fmt::Display for OrderedGraphNameRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// `oxrdf::triple::GraphName` with string-based ordering
#[derive(Eq, PartialEq, Clone, Debug)]
struct OrderedNamedOrBlankNode(NamedOrBlankNode);
impl Ord for OrderedNamedOrBlankNode {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.to_string().cmp(&other.0.to_string())
    }
}
impl PartialOrd for OrderedNamedOrBlankNode {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.to_string().partial_cmp(&other.0.to_string())
    }
}
impl From<NamedOrBlankNode> for OrderedNamedOrBlankNode {
    fn from(value: NamedOrBlankNode) -> Self {
        Self(value)
    }
}

/// `oxrdf::triple::GraphNameRef` with string-based ordering
#[derive(Eq, PartialEq, Clone, Debug)]
struct OrderedNamedOrBlankNodeRef<'a>(NamedOrBlankNodeRef<'a>);
impl Ord for OrderedNamedOrBlankNodeRef<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.to_string().cmp(&other.0.to_string())
    }
}
impl PartialOrd for OrderedNamedOrBlankNodeRef<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.to_string().partial_cmp(&other.0.to_string())
    }
}
impl<'a> From<NamedOrBlankNodeRef<'a>> for OrderedNamedOrBlankNodeRef<'a> {
    fn from(value: NamedOrBlankNodeRef<'a>) -> Self {
        Self(value)
    }
}

#[derive(Debug)]
struct StatementIndexMap {
    document_map: Vec<usize>,
    document_len: usize,
    proof_map: Vec<usize>,
    proof_len: usize,
}

type OrderedGraphViews<'a> = BTreeMap<OrderedGraphNameRef<'a>, GraphView<'a>>;
type OrderedVerifiableCredentialGraphViews<'a> =
    BTreeMap<OrderedGraphNameRef<'a>, VerifiableCredentialView<'a>>;

pub fn derive_proof<R: RngCore>(
    rng: &mut R,
    vcs: &Vec<VcWithDisclosed>,
    deanon_map: &HashMap<NamedOrBlankNode, Term>,
    document_loader: &DocumentLoader,
) -> Result<Dataset, RDFProofsError> {
    for vc in vcs {
        println!("{}", vc.to_string());
    }
    println!("deanon map:\n{:#?}\n", deanon_map);

    // check: VCs must not be empty
    if vcs.is_empty() {
        return Err(RDFProofsError::InvalidVCPairs);
    }

    // TODO:
    // check: each disclosed VCs must be the derived subset of corresponding VCs via deanon map

    // TODO:
    // check: verify VCs

    let verification_methods = vcs
        .iter()
        .map(|VcWithDisclosed { vc, .. }| {
            let vm_triple = vc
                .proof
                .triples_for_predicate(VERIFICATION_METHOD)
                .next()
                .ok_or(RDFProofsError::InvalidVerificationMethod)?;
            match vm_triple.object {
                TermRef::NamedNode(v) => Ok(v),
                _ => Err(RDFProofsError::InvalidVerificationMethodURL),
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let public_keys = verification_methods
        .iter()
        .map(|vm| document_loader.get_public_key(*vm))
        .collect::<Result<Vec<_>, _>>()?;
    println!("verification methods:\n{:#?}\n", verification_methods);
    println!("public keys:\n{:#?}\n", public_keys);

    // get disclosed VCs, where `proofValue` is removed if any
    let disclosed_vcs = vcs
        .iter()
        .map(|VcWithDisclosed { disclosed, .. }| disclosed)
        .map(|VerifiableCredential { document, proof }| {
            VerifiableCredential::new(
                // clone document and proof without `proofValue`
                Graph::from_iter(document),
                Graph::from_iter(proof.iter().filter(|t| t.predicate != PROOF_VALUE)),
            )
        })
        .collect();

    // build VP (without proof yet) based on disclosed VCs
    let (vp, vc_graph_names) = build_vp(&disclosed_vcs)?;
    println!("vp:\n{}\n", vp.to_string());

    // canonicalize VP
    let c14n_map_for_disclosed = issue(&vp)?;
    let canonicalized_vp = relabel(&vp, &c14n_map_for_disclosed)?;
    println!("issued identifiers map:\n{:#?}\n", c14n_map_for_disclosed);
    println!("canonicalized VP:\n{}", serialize(&canonicalized_vp));

    // extract `proofValue`s from original VCs
    let (original_vcs, proof_values): (Vec<_>, Vec<_>) = vcs
        .iter()
        .map(|VcWithDisclosed { vc, .. }| vc)
        .map(|VerifiableCredential { document, proof }| {
            // get `proofValue`s from original VCs
            let proof_value_triple = proof
                .iter()
                .find(|t| t.predicate == PROOF_VALUE)
                .ok_or(RDFProofsError::VCWithoutProofValue)?;
            let proof_value = match proof_value_triple.object {
                TermRef::Literal(l) => Ok(l.value()),
                _ => Err(RDFProofsError::VCWithInvalidProofValue),
            }?;
            Ok((
                VerifiableCredential::new(
                    // clone document and proof without `proofValue`
                    Graph::from_iter(document),
                    Graph::from_iter(proof.iter().filter(|t| t.predicate != PROOF_VALUE)),
                ),
                proof_value,
            ))
        })
        .collect::<Result<Vec<_>, RDFProofsError>>()?
        .into_iter()
        .unzip();

    // canonicalize original VCs
    let c14n_original_vcs = canonicalize_original_vcs(&original_vcs)?;
    let mut c14n_original_vcs_map = HashMap::<String, String>::new();
    for CanonicalVerifiableCredentialTriples {
        document_issued_identifiers_map,
        proof_issued_identifiers_map,
        ..
    } in &c14n_original_vcs
    {
        for (k, v) in document_issued_identifiers_map {
            if c14n_original_vcs_map.contains_key(k) {
                return Err(RDFProofsError::BlankNodeCollision);
            } else {
                c14n_original_vcs_map.insert(k.to_string(), v.to_string());
            }
        }
        for (k, v) in proof_issued_identifiers_map {
            if c14n_original_vcs_map.contains_key(k) {
                return Err(RDFProofsError::BlankNodeCollision);
            } else {
                c14n_original_vcs_map.insert(k.to_string(), v.to_string());
            }
        }
    }

    // construct extended deanonymization map
    let extended_deanon_map =
        extend_deanon_map(deanon_map, &c14n_map_for_disclosed, &c14n_original_vcs_map)?;
    println!("extended deanon map:");
    for (f, t) in &extended_deanon_map {
        println!("{}: {}", f.to_string(), t.to_string());
    }
    println!("");

    // decompose canonicalized VP into graphs
    let VpGraphs {
        metadata: vp_metadata,
        proof: vp_proof,
        filters: filters_graph,
        disclosed_vcs: c14n_disclosed_vc_graphs,
    } = decompose_vp(&canonicalized_vp)?;
    println!("VP metadata:\n{}\n", vp_metadata);
    println!("VP proof graph:\n{}\n", vp_proof);
    println!("filter graphs:");
    for (_, filter_graph) in &filters_graph {
        println!("{}", filter_graph);
    }
    println!("");
    println!("disclosed VC graphs:");
    for (k, vc) in &c14n_disclosed_vc_graphs {
        println!("{}:", k);
        println!("{}", vc.document);
        println!("{}", vc.proof);
    }

    // reorder the original VCs and proof values
    // according to the order of canonicalized graph names of disclosed VCs
    let (c14n_original_vc_triples, ordered_proof_values) = reorder_vcs(
        &c14n_original_vcs,
        &proof_values,
        &c14n_disclosed_vc_graphs,
        &extended_deanon_map,
        &vc_graph_names,
    )?;

    // assert the keys of two VC graphs are equivalent
    if !c14n_original_vc_triples
        .keys()
        .eq(c14n_disclosed_vc_graphs.keys())
    {
        return Err(RDFProofsError::Other(
            "gen_index_map: the keys of two VC graphs must be equivalent".to_string(),
        ));
    }

    // convert to Vecs
    let original_vec = c14n_original_vc_triples
        .into_iter()
        .map(|(_, v)| v.into())
        .collect::<Vec<VerifiableCredentialTriples>>();
    let disclosed_vec = c14n_disclosed_vc_graphs
        .into_iter()
        .map(|(_, v)| v.into())
        .collect::<Vec<VerifiableCredentialTriples>>();
    let proof_values_vec = ordered_proof_values
        .into_iter()
        .map(|(_, v)| v)
        .collect::<Vec<_>>();

    println!("canonicalized original VC graphs (sorted):");
    for VerifiableCredentialTriples { document, proof } in &original_vec {
        println!(
            "document:\n{}",
            document
                .iter()
                .map(|t| format!("{} .\n", t.to_string()))
                .reduce(|l, r| format!("{}{}", l, r))
                .unwrap()
        );
        println!(
            "proof:\n{}",
            proof
                .iter()
                .map(|t| format!("{} .\n", t.to_string()))
                .reduce(|l, r| format!("{}{}", l, r))
                .unwrap()
        );
    }
    println!("canonicalized disclosed VC graphs (sorted):");
    for VerifiableCredentialTriples { document, proof } in &disclosed_vec {
        println!(
            "document:\n{}",
            document
                .iter()
                .map(|t| format!("{} .\n", t.to_string()))
                .reduce(|l, r| format!("{}{}", l, r))
                .unwrap()
        );
        println!(
            "proof:\n{}",
            proof
                .iter()
                .map(|t| format!("{} .\n", t.to_string()))
                .reduce(|l, r| format!("{}{}", l, r))
                .unwrap()
        );
    }

    // generate index map
    let index_map = gen_index_map(&original_vec, &disclosed_vec, &extended_deanon_map)?;
    println!("index_map:\n{:#?}\n", index_map);

    // derive proof value
    let derived_proof_value = derive_proof_value(
        rng,
        original_vec,
        disclosed_vec,
        public_keys,
        proof_values_vec,
        index_map,
    )?;

    // TODO: add derived proof value to VP

    Ok(canonicalized_vp)
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
) -> Result<GraphView<'a>, RDFProofsError> {
    let mut graphs = remove_graphs(vp_graphs, source, link)?;
    match graphs.pop_first() {
        Some((_, graph)) => {
            if graphs.is_empty() {
                Ok(graph)
            } else {
                Err(RDFProofsError::InvalidVP)
            }
        }
        None => Err(RDFProofsError::InvalidVP),
    }
}

fn deanonymize_subject(
    deanon_map: &HashMap<NamedOrBlankNode, Term>,
    subject: &mut Subject,
) -> Result<(), RDFProofsError> {
    match subject {
        Subject::BlankNode(bnode) => {
            if let Some(v) = deanon_map.get(&NamedOrBlankNode::BlankNode(bnode.clone())) {
                match v {
                    Term::NamedNode(n) => *subject = Subject::NamedNode(n.clone()),
                    Term::BlankNode(n) => *subject = Subject::BlankNode(n.clone()),
                    _ => return Err(RDFProofsError::DeAnonymization),
                }
            }
        }
        Subject::NamedNode(node) => {
            if let Some(v) = deanon_map.get(&NamedOrBlankNode::NamedNode(node.clone())) {
                match v {
                    Term::NamedNode(n) => *subject = Subject::NamedNode(n.clone()),
                    Term::BlankNode(n) => *subject = Subject::BlankNode(n.clone()),
                    _ => return Err(RDFProofsError::DeAnonymization),
                }
            }
        }
        #[cfg(feature = "rdf-star")]
        Subject::Triple(_) => return Err(RDFProofsError::DeAnonymization),
    };
    Ok(())
}

fn deanonymize_named_node(
    deanon_map: &HashMap<NamedOrBlankNode, Term>,
    predicate: &mut NamedNode,
) -> Result<(), RDFProofsError> {
    if let Some(v) = deanon_map.get(&NamedOrBlankNode::NamedNode(predicate.clone())) {
        match v {
            Term::NamedNode(n) => *predicate = n.clone(),
            _ => return Err(RDFProofsError::DeAnonymization),
        }
    }
    Ok(())
}

fn deanonymize_term(
    deanon_map: &HashMap<NamedOrBlankNode, Term>,
    term: &mut Term,
) -> Result<(), RDFProofsError> {
    match term {
        Term::BlankNode(bnode) => {
            if let Some(v) = deanon_map.get(&NamedOrBlankNode::BlankNode(bnode.clone())) {
                *term = v.clone();
            }
        }
        Term::NamedNode(node) => {
            if let Some(v) = deanon_map.get(&NamedOrBlankNode::NamedNode(node.clone())) {
                match v {
                    Term::NamedNode(n) => *term = Term::NamedNode(n.clone()),
                    Term::BlankNode(n) => *term = Term::BlankNode(n.clone()),
                    _ => return Err(RDFProofsError::DeAnonymization),
                }
            }
        }
        Term::Literal(_) => (),
        #[cfg(feature = "rdf-star")]
        Term::Triple(_) => return Err(RDFProofsError::DeAnonymization),
    };
    Ok(())
}

fn canonicalize_original_vcs(
    original_vcs: &Vec<VerifiableCredential>,
) -> Result<Vec<CanonicalVerifiableCredentialTriples>, RDFProofsError> {
    original_vcs
        .iter()
        .map(|VerifiableCredential { document, proof }| {
            let document_issued_identifiers_map = issue_graph(&document)?;
            let proof_issued_identifiers_map = issue_graph(&proof)?;
            let canonicalized_document =
                relabel_graph(&document, &document_issued_identifiers_map)?;
            let canonicalized_proof = relabel_graph(&proof, &proof_issued_identifiers_map)?;
            Ok(CanonicalVerifiableCredentialTriples::new(
                canonicalized_document
                    .iter()
                    .map(|t| t.into_owned())
                    .collect(),
                document_issued_identifiers_map,
                canonicalized_proof.iter().map(|t| t.into_owned()).collect(),
                proof_issued_identifiers_map,
            ))
        })
        .collect::<Result<Vec<_>, RDFProofsError>>()
}

fn build_vp(
    disclosed_vcs: &Vec<VerifiableCredential>,
) -> Result<(Dataset, Vec<BlankNode>), RDFProofsError> {
    let vp_id = BlankNode::default();
    let vp_proof_id = BlankNode::default();
    let vp_proof_graph_id = BlankNode::default();

    let mut vp = Dataset::default();
    vp.insert(QuadRef::new(
        &vp_id,
        TYPE,
        VERIFIABLE_PRESENTATION_TYPE,
        GraphNameRef::DefaultGraph,
    ));
    vp.insert(QuadRef::new(
        &vp_id,
        PROOF,
        &vp_proof_graph_id,
        GraphNameRef::DefaultGraph,
    ));
    vp.insert(QuadRef::new(
        &vp_proof_id,
        TYPE,
        DATA_INTEGRITY_PROOF,
        &vp_proof_graph_id,
    ));
    vp.insert(QuadRef::new(
        &vp_proof_id,
        CRYPTOSUITE,
        LiteralRef::new_simple_literal(CRYPTOSUITE_PROOF),
        &vp_proof_graph_id,
    ));
    vp.insert(QuadRef::new(
        &vp_proof_id,
        PROOF_PURPOSE,
        ASSERTION_METHOD,
        &vp_proof_graph_id,
    ));
    vp.insert(QuadRef::new(
        &vp_proof_id,
        CREATED,
        LiteralRef::new_typed_literal(&format!("{:?}", Utc::now()), xsd::DATE_TIME),
        &vp_proof_graph_id,
    ));

    // convert VC graphs (triples) into VC dataset (quads)
    let mut vc_graph_names = Vec::with_capacity(disclosed_vcs.len());
    let vc_quads = disclosed_vcs
        .iter()
        .map(|VerifiableCredential { document, proof }| {
            let document_graph_name = BlankNode::default();
            let proof_graph_name = BlankNode::default();

            vc_graph_names.push(document_graph_name.clone());

            let document_id = document
                .subject_for_predicate_object(TYPE, VERIFIABLE_CREDENTIAL_TYPE)
                .ok_or(RDFProofsError::VCWithoutVCType)?;

            let mut document_quads: Vec<Quad> = document
                .iter()
                .map(|t| t.into_owned().in_graph(document_graph_name.clone()))
                .collect();

            // add `proof` link from VC document to VC proof graph
            document_quads.push(Quad::new(
                document_id,
                PROOF,
                proof_graph_name.clone(),
                document_graph_name.clone(),
            ));

            let mut proof_quads: Vec<Quad> = proof
                .iter()
                .map(|t| t.into_owned().in_graph(proof_graph_name.clone()))
                .collect();
            document_quads.append(&mut proof_quads);

            Ok((document_graph_name, document_quads))
        })
        .collect::<Result<Vec<_>, RDFProofsError>>()?;

    for (vc_graph_name, vc_quad) in vc_quads {
        vp.insert(QuadRef::new(
            &vp_id,
            VERIFIABLE_CREDENTIAL,
            &vc_graph_name,
            GraphNameRef::DefaultGraph,
        ));
        vp.extend(vc_quad);
    }
    Ok((vp, vc_graph_names))
}

fn dataset_into_ordered_graphs(dataset: &Dataset) -> OrderedGraphViews {
    let graph_name_set = dataset
        .iter()
        .map(|QuadRef { graph_name, .. }| OrderedGraphNameRef(graph_name))
        .collect::<BTreeSet<_>>();

    graph_name_set
        .into_iter()
        .map(|graph_name| (graph_name.clone(), dataset.graph(graph_name)))
        .collect()
}

fn extend_deanon_map(
    deanon_map: &HashMap<NamedOrBlankNode, Term>,
    issued_identifiers_map: &HashMap<String, String>,
    c14n_original_vcs_map: &HashMap<String, String>,
) -> Result<HashMap<NamedOrBlankNode, Term>, RDFProofsError> {
    let mut res = issued_identifiers_map
        .into_iter()
        .map(|(bnid, cnid)| {
            let mapped_bnid = match c14n_original_vcs_map.get(bnid) {
                Some(v) => v,
                None => bnid,
            };
            let bnode = BlankNode::new(mapped_bnid)?;
            let cnid = NamedOrBlankNode::BlankNode(BlankNode::new(cnid)?);
            if let Some(v) = deanon_map.get(&NamedOrBlankNode::BlankNode(bnode.clone())) {
                Ok((cnid, v.clone()))
            } else {
                Ok((cnid, bnode.into()))
            }
        })
        .collect::<Result<HashMap<_, _>, RDFProofsError>>()?;
    for (k, v) in deanon_map {
        if let NamedOrBlankNode::NamedNode(_) = k {
            res.insert(k.clone(), v.clone());
        }
    }
    Ok(res)
}

fn decompose_vp<'a>(vp: &'a Dataset) -> Result<VpGraphs<'a>, RDFProofsError> {
    let mut vp_graphs = dataset_into_ordered_graphs(vp);
    println!("canonicalized VP graphs:");
    for g in vp_graphs.keys() {
        println!("{}:\n{}\n", g, vp_graphs.get(g).unwrap());
    }

    // extract VP metadata (default graph)
    let metadata = vp_graphs
        .remove(&OrderedGraphNameRef(GraphNameRef::DefaultGraph))
        .ok_or(RDFProofsError::Other(
            "VP graphs must have default graph".to_owned(),
        ))?;

    // extract VP proof graph
    let proof = remove_graph(&mut vp_graphs, &metadata, PROOF)?;

    // extract filter graphs if any
    let filters = remove_graphs(&mut vp_graphs, &proof, FILTER)?;

    // extract VC graphs
    let vcs = remove_graphs(&mut vp_graphs, &metadata, VERIFIABLE_CREDENTIAL)?;

    // extract VC proof graphs
    let disclosed_vcs = vcs
        .into_iter()
        .map(|(vc_graph_name, vc)| {
            let vc_proof = remove_graph(&mut vp_graphs, &vc, PROOF)?;
            Ok((vc_graph_name, VerifiableCredentialView::new(vc, vc_proof)))
        })
        .collect::<Result<OrderedVerifiableCredentialGraphViews, RDFProofsError>>()?;

    // check if `vp_graphs` is empty
    if !vp_graphs.is_empty() {
        return Err(RDFProofsError::InvalidVP);
    }

    Ok(VpGraphs {
        metadata,
        proof,
        filters,
        disclosed_vcs,
    })
}

fn reorder_vcs<'a>(
    c14n_original_vcs: &'a Vec<CanonicalVerifiableCredentialTriples>,
    proof_values: &'a Vec<&str>,
    c14n_disclosed_vc_graphs: &OrderedVerifiableCredentialGraphViews<'a>,
    extended_deanon_map: &'a HashMap<NamedOrBlankNode, Term>,
    vc_graph_names: &Vec<BlankNode>,
) -> Result<
    (
        BTreeMap<OrderedGraphNameRef<'a>, &'a CanonicalVerifiableCredentialTriples>,
        BTreeMap<OrderedGraphNameRef<'a>, &'a str>,
    ),
    RDFProofsError,
> {
    let mut ordered_vcs = BTreeMap::new();
    let mut ordered_proof_values = BTreeMap::new();

    for k in c14n_disclosed_vc_graphs.keys() {
        let vc_graph_name_c14n: &GraphNameRef = k.into();
        let vc_graph_name = match vc_graph_name_c14n {
            GraphNameRef::BlankNode(n) => match extended_deanon_map.get(&(*n).into()) {
                Some(Term::BlankNode(n)) => Ok(n),
                _ => Err(RDFProofsError::Other("invalid VC graph name".to_string())),
            },
            _ => Err(RDFProofsError::Other("invalid VC graph name".to_string())),
        }?;
        let index = vc_graph_names
            .iter()
            .position(|v| v == vc_graph_name)
            .ok_or(RDFProofsError::Other("invalid VC index".to_string()))?;
        let vc = c14n_original_vcs
            .get(index)
            .ok_or(RDFProofsError::Other("invalid VC index".to_string()))?;
        let proof_value = proof_values.get(index).ok_or(RDFProofsError::Other(
            "invalid proof value index".to_string(),
        ))?;
        ordered_vcs.insert(k.clone(), vc);
        ordered_proof_values.insert(k.clone(), proof_value.to_owned());
    }

    Ok((ordered_vcs, ordered_proof_values))
}

fn gen_index_map(
    c14n_original_vc_triples: &Vec<VerifiableCredentialTriples>,
    c14n_disclosed_vc_triples: &Vec<VerifiableCredentialTriples>,
    extended_deanon_map: &HashMap<NamedOrBlankNode, Term>,
) -> Result<Vec<StatementIndexMap>, RDFProofsError> {
    let mut c14n_disclosed_vc_triples_cloned = (*c14n_disclosed_vc_triples).clone();

    // deanonymize each disclosed VC triples, keeping their orders
    for VerifiableCredentialTriples { document, proof } in &mut c14n_disclosed_vc_triples_cloned {
        for triple in document.into_iter() {
            deanonymize_subject(extended_deanon_map, &mut triple.subject)?;
            deanonymize_named_node(extended_deanon_map, &mut triple.predicate)?;
            deanonymize_term(extended_deanon_map, &mut triple.object)?;
        }
        for triple in proof.into_iter() {
            deanonymize_subject(extended_deanon_map, &mut triple.subject)?;
            deanonymize_named_node(extended_deanon_map, &mut triple.predicate)?;
            deanonymize_term(extended_deanon_map, &mut triple.object)?;
        }
    }
    println!("deanonymized canonicalized disclosed VC graphs:");
    for VerifiableCredentialTriples { document, proof } in &c14n_disclosed_vc_triples_cloned {
        println!(
            "document:\n{}",
            document
                .iter()
                .map(|t| format!("{} .\n", t.to_string()))
                .reduce(|l, r| format!("{}{}", l, r))
                .unwrap()
        );
        println!(
            "proof:\n{}",
            proof
                .iter()
                .map(|t| format!("{} .\n", t.to_string()))
                .reduce(|l, r| format!("{}{}", l, r))
                .unwrap()
        );
    }

    // calculate index mapping
    let index_map = c14n_disclosed_vc_triples_cloned
        .iter()
        .zip(c14n_original_vc_triples)
        .map(
            |(
                VerifiableCredentialTriples {
                    document: disclosed_document,
                    proof: disclosed_proof,
                },
                VerifiableCredentialTriples {
                    document: original_document,
                    proof: original_proof,
                },
            )| {
                let document_map = disclosed_document
                    .iter()
                    .map(|disclosed_triple| {
                        original_document
                            .iter()
                            .position(|original_triple| *disclosed_triple == *original_triple)
                            .ok_or(RDFProofsError::DisclosedVCIsNotSubsetOfOriginalVC)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let proof_map = disclosed_proof
                    .iter()
                    .map(|disclosed_triple| {
                        original_proof
                            .iter()
                            .position(|original_triple| *disclosed_triple == *original_triple)
                            .ok_or(RDFProofsError::DisclosedVCIsNotSubsetOfOriginalVC)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let document_len = original_document.len();
                let proof_len = original_proof.len();
                Ok(StatementIndexMap {
                    document_map,
                    document_len,
                    proof_map,
                    proof_len,
                })
            },
        )
        .collect::<Result<Vec<_>, RDFProofsError>>()?;

    Ok(index_map)
}

fn derive_proof_value<R: RngCore>(
    rng: &mut R,
    original_vc_triples: Vec<VerifiableCredentialTriples>,
    disclosed_vc_triples: Vec<VerifiableCredentialTriples>,
    public_keys: Vec<BBSPublicKeyG2<Bls12_381>>,
    proof_values: Vec<&str>,
    index_map: Vec<StatementIndexMap>,
) -> Result<String, RDFProofsError> {
    // TODO: extract parameters and issuer public keys
    let message_count = original_vc_triples.len() * 3;
    let params = generate_params(message_count);

    // reorder disclosed VC triples according to index map
    let reordered_disclosed_vc_triples = disclosed_vc_triples
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
        .collect::<Result<Vec<_>, RDFProofsError>>()?;

    println!(
        "reordered_disclosed_vc_triples:\n{:#?}\n",
        reordered_disclosed_vc_triples
    );

    // identify disclosed and undisclosed terms
    let disclosed_and_undisclosed_terms = reordered_disclosed_vc_triples
        .iter()
        .zip(original_vc_triples)
        .enumerate()
        .map(|(i, (disclosed_vc_triples, original_vc_triples))| {
            get_disclosed_and_undisclosed_terms(disclosed_vc_triples, &original_vc_triples, i)
        })
        .collect::<Result<Vec<_>, RDFProofsError>>()?;
    println!(
        "disclosed_and_undisclosed:\n{:#?}\n",
        disclosed_and_undisclosed_terms
    );
    println!("proof values: {:?}", proof_values);

    // identify equivalent witnesses
    let mut equivs: BTreeMap<OrderedNamedOrBlankNode, Vec<(usize, usize)>> = BTreeMap::new();
    for DisclosedAndUndisclosedTerms {
        equivs: partial_equivs,
        ..
    } in disclosed_and_undisclosed_terms
    {
        for (k, v) in partial_equivs {
            equivs.entry(k.into()).or_default().extend(v.clone());
        }
    }
    println!("equivs:\n{:#?}\n", equivs);

    // TODO: generate proofs
    // let statement = disclosed_and_undisclosed_terms.iter().zip(public_keys).map(
    //     |(
    //         DisclosedAndUndisclosed {
    //             document_terms,
    //             proof_terms,
    //             document_equivs,
    //             proof_equivs,
    //         },
    //         public_key,
    //     )| {
    //         PoKBBSSignatureG1Stmt::new_statement_from_params(params, public_key, )
    //     },
    // );

    todo!();
}

#[derive(Debug)]
struct DisclosedAndUndisclosedTerms {
    disclosed: BTreeMap<usize, Fr>,
    undisclosed: BTreeMap<usize, Fr>,
    equivs: HashMap<NamedOrBlankNode, Vec<(usize, usize)>>,
}

#[derive(Debug)]
struct Equivs<'a> {
    document: BTreeMap<OrderedNamedOrBlankNodeRef<'a>, Vec<(usize, usize)>>,
    proof: BTreeMap<OrderedNamedOrBlankNodeRef<'a>, Vec<(usize, usize)>>,
}

fn get_disclosed_and_undisclosed_terms(
    disclosed_vc_triples: &DisclosedVerifiableCredential,
    original_vc_triples: &VerifiableCredentialTriples,
    vc_index: usize,
) -> Result<DisclosedAndUndisclosedTerms, RDFProofsError> {
    let mut disclosed_terms = BTreeMap::<usize, Fr>::new();
    let mut undisclosed_terms = BTreeMap::<usize, Fr>::new();
    let mut equivs = HashMap::<NamedOrBlankNode, Vec<(usize, usize)>>::new();

    let DisclosedVerifiableCredential {
        document: disclosed_document,
        proof: disclosed_proof,
    } = disclosed_vc_triples;
    let VerifiableCredentialTriples {
        document: original_document,
        proof: original_proof,
    } = original_vc_triples;

    for (j, disclosed_triple) in disclosed_document {
        let subject_index = 3 * j;
        let original = original_document
            .get(*j)
            .ok_or(RDFProofsError::DeriveProofValue)?
            .clone();
        build_disclosed_and_undisclosed_terms(
            disclosed_triple,
            subject_index,
            vc_index,
            &original,
            &mut disclosed_terms,
            &mut undisclosed_terms,
            &mut equivs,
        )?;
    }

    let delimiter_index = disclosed_document.len() * 3;
    let proof_index = delimiter_index + 1;
    let delimiter = get_delimiter()?;
    disclosed_terms.insert(delimiter_index, delimiter);

    for (j, disclosed_triple) in disclosed_proof {
        let subject_index = 3 * j + proof_index;
        let original = original_proof
            .get(*j)
            .ok_or(RDFProofsError::DeriveProofValue)?
            .clone();
        build_disclosed_and_undisclosed_terms(
            disclosed_triple,
            subject_index,
            vc_index,
            &original,
            &mut disclosed_terms,
            &mut undisclosed_terms,
            &mut equivs,
        )?;
    }
    Ok(DisclosedAndUndisclosedTerms {
        disclosed: disclosed_terms,
        undisclosed: undisclosed_terms,
        equivs,
    })
}

fn build_disclosed_and_undisclosed_terms(
    disclosed_triple: &Option<Triple>,
    subject_index: usize,
    vc_index: usize,
    original: &Triple,
    disclosed_terms: &mut BTreeMap<usize, Fr>,
    undisclosed_terms: &mut BTreeMap<usize, Fr>,
    equivs: &mut HashMap<NamedOrBlankNode, Vec<(usize, usize)>>,
) -> Result<(), RDFProofsError> {
    let predicate_index = subject_index + 1;
    let object_index = subject_index + 2;

    let hasher = get_hasher();
    let subject_fr = hash_term_to_field((&original.subject).into(), &hasher)?;
    let predicate_fr = hash_term_to_field((&original.predicate).into(), &hasher)?;
    let object_fr = hash_term_to_field((&original.object).into(), &hasher)?;

    match disclosed_triple {
        Some(triple) => {
            match &triple.subject {
                Subject::BlankNode(b) => {
                    undisclosed_terms.insert(subject_index, subject_fr);
                    equivs
                        .entry(NamedOrBlankNode::BlankNode(b.clone().into()))
                        .or_default()
                        .push((vc_index, subject_index));
                }
                Subject::NamedNode(n) if is_nym(n) => {
                    undisclosed_terms.insert(subject_index, subject_fr);
                    equivs
                        .entry(NamedOrBlankNode::NamedNode(n.clone().into()))
                        .or_default()
                        .push((vc_index, subject_index));
                }
                Subject::NamedNode(_) => {
                    disclosed_terms.insert(subject_index, subject_fr);
                }
                #[cfg(feature = "rdf-star")]
                Subject::Triple(_) => return Err(RDFProofsError::DeriveProofValue),
            };

            if is_nym(&triple.predicate) {
                undisclosed_terms.insert(predicate_index, predicate_fr);
                equivs
                    .entry(NamedOrBlankNode::NamedNode(triple.predicate.clone().into()))
                    .or_default()
                    .push((vc_index, predicate_index));
            } else {
                disclosed_terms.insert(predicate_index, predicate_fr);
            };

            match &triple.object {
                Term::BlankNode(b) => {
                    undisclosed_terms.insert(object_index, object_fr);
                    equivs
                        .entry(NamedOrBlankNode::BlankNode(b.clone().into()))
                        .or_default()
                        .push((vc_index, object_index));
                }
                Term::NamedNode(n) if is_nym(n) => {
                    undisclosed_terms.insert(object_index, object_fr);
                    equivs
                        .entry(NamedOrBlankNode::NamedNode(n.clone().into()))
                        .or_default()
                        .push((vc_index, object_index));
                }
                Term::NamedNode(_) | Term::Literal(_) => {
                    disclosed_terms.insert(object_index, object_fr);
                }
                #[cfg(feature = "rdf-star")]
                Term::Triple(_) => return Err(RDFProofsError::DeriveProofValue),
            };
        }

        None => {
            undisclosed_terms.insert(subject_index, subject_fr);
            undisclosed_terms.insert(predicate_index, predicate_fr);
            undisclosed_terms.insert(object_index, object_fr);
        }
    };
    Ok(())
}

fn is_nym(node: &NamedNode) -> bool {
    node.as_str().starts_with(NYM_IRI_PREFIX)
}

#[cfg(test)]
mod tests {
    use crate::{
        error::RDFProofsError,
        loader::DocumentLoader,
        proof::{derive_proof, VcWithDisclosed},
        tests::{get_graph_from_ntriples_str, DOCUMENT_LOADER_NTRIPLES},
        vc::VerifiableCredential,
    };
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use oxrdf::{BlankNode, Graph, NamedNode};
    use oxttl::NTriplesParser;
    use std::{collections::HashMap, io::Cursor};

    #[test]
    fn derive_proof_simple() -> Result<(), RDFProofsError> {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed

        let document_loader: DocumentLoader =
            get_graph_from_ntriples_str(DOCUMENT_LOADER_NTRIPLES).into();

        let vc_ntriples = r#"
<did:example:john> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
<did:example:john> <http://schema.org/name> "John Smith" .
<did:example:john> <http://example.org/vocab/isPatientOf> _:a91b3e .
_:a91b3e <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
_:a91b3e <http://example.org/vocab/lotNumber> "0000001" .
_:a91b3e <http://example.org/vocab/vaccinationDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:a91b3e <http://example.org/vocab/vaccine> <http://example.org/vaccine/a> .
_:a91b3e <http://example.org/vocab/vaccine> <http://example.org/vaccine/b> .
<http://example.org/vcred/00> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:john> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
"#;
        let vc_proof_ntriples = r#"
_:6b92db <https://w3id.org/security#proofValue> "ugZveToWB9bUAm3RDFWeORovPDYdIgNWbsquhn334R78TCG86fad_3JiA6yh_f-bsnHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ" .
_:6b92db <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:6b92db <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:6b92db <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:6b92db <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:6b92db <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
"#;

        let disclosed_vc_ntriples = r#"
_:e0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
_:e0 <http://example.org/vocab/isPatientOf> _:a91b3e .
_:a91b3e <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
_:a91b3e <http://example.org/vocab/vaccine> _:e1 .
_:a91b3e <http://example.org/vocab/vaccine> _:e2 .
<http://example.org/vcred/00> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#credentialSubject> _:e0 .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
"#;
        let disclosed_vc_proof_ntriples = r#"
_:6b92db <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:6b92db <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:6b92db <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:6b92db <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:6b92db <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
"#;

        let mut deanon_map = HashMap::new();
        deanon_map.insert(
            BlankNode::new_unchecked("e0").into(),
            NamedNode::new_unchecked("did:example:john").into(),
        );
        deanon_map.insert(
            BlankNode::new_unchecked("e1").into(),
            NamedNode::new_unchecked("http://example.org/vaccine/a").into(),
        );
        deanon_map.insert(
            BlankNode::new_unchecked("e2").into(),
            NamedNode::new_unchecked("http://example.org/vaccine/b").into(),
        );

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

        let vc_with_disclosed = VcWithDisclosed::new(vc, disclosed);
        let vcs = vec![vc_with_disclosed];
        let derived_proof = derive_proof(&mut rng, &vcs, &deanon_map, &document_loader);

        Ok(())
    }
}
