use super::constants::{CRYPTOSUITE_PROOF, NYM_IRI_PREFIX};
use crate::{
    common::{get_delimiter, get_hasher, hash_term_to_field, Fr, ProofG1},
    context::{
        ASSERTION_METHOD, CREATED, CRYPTOSUITE, DATA_INTEGRITY_PROOF, FILTER, MULTIBASE, PROOF,
        PROOF_PURPOSE, PROOF_VALUE, VERIFIABLE_CREDENTIAL, VERIFIABLE_CREDENTIAL_TYPE,
        VERIFIABLE_PRESENTATION_TYPE, VERIFICATION_METHOD,
    },
    error::RDFProofsError,
    keygen::generate_params,
    loader::DocumentLoader,
    signature::verify,
    vc::{
        CanonicalVerifiableCredentialTriples, DisclosedVerifiableCredential, VerifiableCredential,
        VerifiableCredentialTriples, VerifiableCredentialView,
    },
};
use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
use bbs_plus::prelude::{PublicKeyG2 as BBSPublicKeyG2, SignatureG1 as BBSSignatureG1};
use blake2::Blake2b512;
use chrono::offset::Utc;
use multibase::Base;
use oxrdf::{
    dataset::GraphView,
    vocab::{rdf::TYPE, xsd},
    BlankNode, Dataset, Graph, GraphNameRef, LiteralRef, NamedNode, NamedNodeRef, NamedOrBlankNode,
    NamedOrBlankNodeRef, Quad, QuadRef, Subject, Term, TermRef, Triple,
};
use proof_system::{
    prelude::{EqualWitnesses, MetaStatements},
    proof_spec::ProofSpec,
    statement::{bbs_plus::PoKBBSSignatureG1 as PoKBBSSignatureG1Stmt, Statements},
    witness::{PoKBBSSignatureG1 as PoKBBSSignatureG1Wit, Witnesses},
};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
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
    proof_graph_name: OrderedGraphNameRef<'a>,
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

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename = "0")]
struct StatementIndexMap {
    #[serde(rename = "1")]
    document_map: Vec<usize>,
    #[serde(rename = "2")]
    document_len: usize,
    #[serde(rename = "3")]
    proof_map: Vec<usize>,
    #[serde(rename = "4")]
    proof_len: usize,
}

type OrderedGraphViews<'a> = BTreeMap<OrderedGraphNameRef<'a>, GraphView<'a>>;
type OrderedVerifiableCredentialGraphViews<'a> =
    BTreeMap<OrderedGraphNameRef<'a>, VerifiableCredentialView<'a>>;

/// derive VP from VCs, disclosed VCs, and deanonymization map
pub fn derive_proof<R: RngCore>(
    rng: &mut R,
    vcs: &Vec<VcWithDisclosed>,
    deanon_map: &HashMap<NamedOrBlankNode, Term>,
    nonce: Option<&[u8]>,
    document_loader: &DocumentLoader,
) -> Result<Dataset, RDFProofsError> {
    for vc in vcs {
        println!("{}", vc.to_string());
    }
    println!("deanon map:\n{:#?}\n", deanon_map);

    // VCs must not be empty
    if vcs.is_empty() {
        return Err(RDFProofsError::InvalidVCPairs);
    }

    // TODO:
    // check: each disclosed VCs must be the derived subset of corresponding VCs via deanon map

    // get issuer public keys
    let public_keys = vcs
        .iter()
        .map(|VcWithDisclosed { vc, .. }| get_public_keys(&vc.proof, document_loader))
        .collect::<Result<Vec<_>, _>>()?;
    println!("public keys:\n{:#?}\n", public_keys);

    // verify VCs
    vcs.iter()
        .map(|VcWithDisclosed { vc, .. }| verify(vc, document_loader))
        .collect::<Result<(), _>>()?;

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
    let c14n_map_for_disclosed = rdf_canon::issue(&vp)?;
    let canonicalized_vp = rdf_canon::relabel(&vp, &c14n_map_for_disclosed)?;
    println!("issued identifiers map:\n{:#?}\n", c14n_map_for_disclosed);
    println!(
        "canonicalized VP:\n{}",
        rdf_canon::serialize(&canonicalized_vp)
    );

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
        metadata: _,
        proof: vp_proof,
        proof_graph_name: vp_proof_graph_name,
        filters: _filters_graph,
        disclosed_vcs: c14n_disclosed_vc_graphs,
    } = decompose_vp(&canonicalized_vp)?;

    // reorder the original VC graphs and proof values
    // according to the order of canonicalized graph names of disclosed VCs
    let (c14n_original_vc_triples, ordered_proof_values) = reorder_vc_graphs(
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
        &canonicalized_vp,
        nonce,
    )?;

    // add derived proof value to VP
    let vp_proof_subject = vp_proof
        .subject_for_predicate_object(TYPE, DATA_INTEGRITY_PROOF)
        .ok_or(RDFProofsError::InvalidVP)?;
    let vp_proof_value_quad = QuadRef::new(
        vp_proof_subject,
        PROOF_VALUE,
        LiteralRef::new_typed_literal(&derived_proof_value, MULTIBASE),
        vp_proof_graph_name,
    );
    let mut canonicalized_vp_quads = canonicalized_vp.into_iter().collect::<Vec<_>>();
    canonicalized_vp_quads.push(vp_proof_value_quad);

    Ok(Dataset::from_iter(canonicalized_vp_quads))
}

/// verify VP
pub fn verify_proof<R: RngCore>(
    rng: &mut R,
    vp: &Dataset,
    nonce: Option<&[u8]>,
    document_loader: &DocumentLoader,
) -> Result<(), RDFProofsError> {
    println!("VP:\n{}", rdf_canon::serialize(&vp));

    // decompose VP into graphs
    let VpGraphs {
        proof: vp_proof_with_value,
        proof_graph_name,
        ..
    } = decompose_vp(vp)?;
    let proof_graph_name: GraphNameRef = proof_graph_name.into();

    // get proof value
    let proof_value_triple = vp_proof_with_value
        .triples_for_predicate(PROOF_VALUE)
        .next()
        .ok_or(RDFProofsError::InvalidVP)?;
    let proof_value_encoded = match proof_value_triple.object {
        TermRef::Literal(v) => Ok(v.value()),
        _ => Err(RDFProofsError::InvalidVP),
    }?;

    // drop proof value from VP proof
    let vp_without_proof_value = Dataset::from_iter(
        vp.iter()
            .filter(|q| !(q.predicate == PROOF_VALUE && q.graph_name == proof_graph_name)),
    );

    // canonicalize VP
    let c14n_map_for_disclosed = rdf_canon::issue(&vp_without_proof_value)?;
    let canonicalized_vp = rdf_canon::relabel(&vp_without_proof_value, &c14n_map_for_disclosed)?;
    println!(
        "canonicalized VP:\n{}",
        rdf_canon::serialize(&canonicalized_vp)
    );

    // TODO: check VP

    // decompose canonicalized VP into graphs
    let VpGraphs {
        metadata: _,
        proof: _,
        proof_graph_name: _,
        filters: _filters_graph,
        disclosed_vcs: c14n_disclosed_vc_graphs,
    } = decompose_vp(&canonicalized_vp)?;

    // get issuer public keys
    let public_keys = c14n_disclosed_vc_graphs
        .iter()
        .map(|(_, vc)| get_public_keys_from_graphview(&vc.proof, document_loader))
        .collect::<Result<Vec<_>, _>>()?;
    println!("public_keys:\n{:#?}\n", public_keys);

    // convert to Vecs
    let disclosed_vec = c14n_disclosed_vc_graphs
        .into_iter()
        .map(|(_, v)| v.into())
        .collect::<Vec<VerifiableCredentialTriples>>();

    // deserialize proof value into proof and index_map
    let (_, proof_value_bytes) = multibase::decode(proof_value_encoded)?;
    let ProofWithIndexMap {
        proof: proof_bytes,
        index_map,
    } = serde_cbor::from_slice(&proof_value_bytes)?;
    let proof = ProofG1::deserialize_compressed(&*proof_bytes)?;
    println!("proof:\n{:#?}\n", proof);
    println!("index_map:\n{:#?}\n", index_map);

    // reorder statements according to index map
    let reordered_vc_triples = reorder_vc_triples(&disclosed_vec, &index_map)?;
    println!(
        "reordered_disclosed_vc_triples:\n{:#?}\n",
        reordered_vc_triples
    );

    // identify disclosed terms
    let disclosed_terms = reordered_vc_triples
        .iter()
        .enumerate()
        .map(|(i, disclosed_vc_triples)| get_disclosed_terms(disclosed_vc_triples, i))
        .collect::<Result<Vec<_>, RDFProofsError>>()?;
    println!("disclosed_terms:\n{:#?}\n", disclosed_terms);

    let params_and_pks = disclosed_terms
        .iter()
        .zip(public_keys)
        .map(|(t, pk)| (generate_params(t.term_count), pk));

    // merge each partial equivs
    let mut equivs: BTreeMap<OrderedNamedOrBlankNode, Vec<(usize, usize)>> = BTreeMap::new();
    for DisclosedTerms {
        equivs: partial_equivs,
        ..
    } in &disclosed_terms
    {
        for (k, v) in partial_equivs {
            equivs
                .entry(k.clone().into())
                .or_default()
                .extend(v.clone());
        }
    }
    // drop single-element vecs from equivs
    let equivs: BTreeMap<OrderedNamedOrBlankNode, Vec<(usize, usize)>> =
        equivs.into_iter().filter(|(_, v)| v.len() > 1).collect();

    // build statements
    let mut statements = Statements::<Bls12_381, <Bls12_381 as Pairing>::G1Affine>::new();
    for (DisclosedTerms { disclosed, .. }, (params, public_key)) in
        disclosed_terms.iter().zip(params_and_pks)
    {
        statements.add(PoKBBSSignatureG1Stmt::new_statement_from_params(
            params,
            public_key,
            disclosed.clone(),
        ));
    }

    // build meta statements
    let mut meta_statements = MetaStatements::new();
    for (_, equiv_vec) in equivs {
        let equiv_set: BTreeSet<(usize, usize)> = equiv_vec.into_iter().collect();
        meta_statements.add_witness_equality(EqualWitnesses(equiv_set));
    }

    // build context
    let serialized_vp = rdf_canon::serialize(&canonicalized_vp).into_bytes();
    let serialized_vp_with_index_map = ProofWithIndexMap {
        proof: serialized_vp,
        index_map: index_map.clone(),
    };
    let context = serde_cbor::to_vec(&serialized_vp_with_index_map)?;

    // build proof spec
    let proof_spec = ProofSpec::new(statements, meta_statements, vec![], Some(context));
    proof_spec.validate()?;

    // verify proof
    Ok(proof.verify::<R, Blake2b512>(
        rng,
        proof_spec,
        nonce.map(|v| v.to_vec()),
        Default::default(),
    )?)
}

fn get_public_keys(
    proof_graph: &Graph,
    document_loader: &DocumentLoader,
) -> Result<BBSPublicKeyG2<Bls12_381>, RDFProofsError> {
    let vm_triple = proof_graph
        .triples_for_predicate(VERIFICATION_METHOD)
        .next()
        .ok_or(RDFProofsError::InvalidVerificationMethod)?;
    let vm = match vm_triple.object {
        TermRef::NamedNode(v) => Ok(v),
        _ => Err(RDFProofsError::InvalidVerificationMethodURL),
    }?;
    document_loader.get_public_key(vm)
}

// TODO: to be integrated with `get_public_keys`
fn get_public_keys_from_graphview(
    proof_graph: &GraphView,
    document_loader: &DocumentLoader,
) -> Result<BBSPublicKeyG2<Bls12_381>, RDFProofsError> {
    let vm_triple = proof_graph
        .triples_for_predicate(VERIFICATION_METHOD)
        .next()
        .ok_or(RDFProofsError::InvalidVerificationMethod)?;
    let vm = match vm_triple.object {
        TermRef::NamedNode(v) => Ok(v),
        _ => Err(RDFProofsError::InvalidVerificationMethodURL),
    }?;
    document_loader.get_public_key(vm)
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
            let document_issued_identifiers_map = rdf_canon::issue_graph(&document)?;
            let proof_issued_identifiers_map = rdf_canon::issue_graph(&proof)?;
            let canonicalized_document =
                rdf_canon::relabel_graph(&document, &document_issued_identifiers_map)?;
            let canonicalized_proof =
                rdf_canon::relabel_graph(&proof, &proof_issued_identifiers_map)?;
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

    // extract VP metadata (default graph)
    let metadata = vp_graphs
        .remove(&OrderedGraphNameRef(GraphNameRef::DefaultGraph))
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

fn reorder_vc_graphs<'a>(
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

fn reorder_vc_triples(
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

fn derive_proof_value<R: RngCore>(
    rng: &mut R,
    original_vc_triples: Vec<VerifiableCredentialTriples>,
    disclosed_vc_triples: Vec<VerifiableCredentialTriples>,
    public_keys: Vec<BBSPublicKeyG2<Bls12_381>>,
    proof_values: Vec<&str>,
    index_map: Vec<StatementIndexMap>,
    canonicalized_vp: &Dataset,
    nonce: Option<&[u8]>,
) -> Result<String, RDFProofsError> {
    // reorder disclosed VC triples according to index map
    let reordered_disclosed_vc_triples = reorder_vc_triples(&disclosed_vc_triples, &index_map)?;
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

    let params_and_pks = disclosed_and_undisclosed_terms
        .iter()
        .zip(public_keys)
        .map(|(t, pk)| (generate_params(t.term_count), pk));

    // merge each partial equivs
    let mut equivs: BTreeMap<OrderedNamedOrBlankNode, Vec<(usize, usize)>> = BTreeMap::new();
    for DisclosedAndUndisclosedTerms {
        equivs: partial_equivs,
        ..
    } in &disclosed_and_undisclosed_terms
    {
        for (k, v) in partial_equivs {
            equivs
                .entry(k.clone().into())
                .or_default()
                .extend(v.clone());
        }
    }
    // drop single-element vecs from equivs
    let equivs: BTreeMap<OrderedNamedOrBlankNode, Vec<(usize, usize)>> =
        equivs.into_iter().filter(|(_, v)| v.len() > 1).collect();

    // build statements
    let mut statements = Statements::<Bls12_381, <Bls12_381 as Pairing>::G1Affine>::new();
    for (DisclosedAndUndisclosedTerms { disclosed, .. }, (params, public_key)) in
        disclosed_and_undisclosed_terms.iter().zip(params_and_pks)
    {
        statements.add(PoKBBSSignatureG1Stmt::new_statement_from_params(
            params,
            public_key,
            disclosed.clone(),
        ));
    }

    // build meta statements
    let mut meta_statements = MetaStatements::new();
    for (_, equiv_vec) in equivs {
        let equiv_set: BTreeSet<(usize, usize)> = equiv_vec.into_iter().collect();
        meta_statements.add_witness_equality(EqualWitnesses(equiv_set));
    }

    // build context
    let serialized_vp = rdf_canon::serialize(canonicalized_vp).into_bytes();
    let serialized_vp_with_index_map = ProofWithIndexMap {
        proof: serialized_vp,
        index_map: index_map.clone(),
    };
    let context = serde_cbor::to_vec(&serialized_vp_with_index_map)?;

    // build proof spec
    let proof_spec = ProofSpec::new(statements, meta_statements, vec![], Some(context));
    proof_spec.validate()?;

    // build witnesses
    let mut witnesses = Witnesses::new();
    for (DisclosedAndUndisclosedTerms { undisclosed, .. }, proof_value) in
        disclosed_and_undisclosed_terms.iter().zip(proof_values)
    {
        let (_, proof_value_bytes) = multibase::decode(proof_value)?;
        let signature = BBSSignatureG1::<Bls12_381>::deserialize_compressed(&*proof_value_bytes)?;
        witnesses.add(PoKBBSSignatureG1Wit::new_as_witness(
            signature,
            undisclosed.clone(),
        ));
    }
    println!("witnesses:\n{:#?}\n", witnesses);

    // build proof
    let proof = ProofG1::new::<R, Blake2b512>(
        rng,
        proof_spec,
        witnesses,
        nonce.map(|v| v.to_vec()),
        Default::default(),
    )?
    .0;
    println!("proof:\n{:#?}\n", proof);

    // serialize proof and index_map
    serialize_proof_with_index_map(proof, &index_map)
}

fn serialize_proof_with_index_map(
    proof: ProofG1,
    index_map: &Vec<StatementIndexMap>,
) -> Result<String, RDFProofsError> {
    // TODO: optimize
    // TODO: use multicodec
    let mut proof_bytes_compressed = Vec::new();
    proof.serialize_compressed(&mut proof_bytes_compressed)?;

    let proof_with_index_map = ProofWithIndexMap {
        proof: proof_bytes_compressed,
        index_map: index_map.clone(),
    };
    let proof_with_index_map_cbor = serde_cbor::to_vec(&proof_with_index_map)?;
    let proof_with_index_map_multibase =
        multibase::encode(Base::Base64Url, proof_with_index_map_cbor);
    Ok(proof_with_index_map_multibase)
}

#[serde_as]
#[derive(Serialize, Deserialize)]
struct ProofWithIndexMap {
    #[serde_as(as = "Bytes")]
    proof: Vec<u8>,
    index_map: Vec<StatementIndexMap>,
}

#[derive(Debug)]
struct DisclosedTerms {
    disclosed: BTreeMap<usize, Fr>,
    equivs: HashMap<NamedOrBlankNode, Vec<(usize, usize)>>,
    term_count: usize,
}

fn get_disclosed_terms(
    disclosed_vc_triples: &DisclosedVerifiableCredential,
    vc_index: usize,
) -> Result<DisclosedTerms, RDFProofsError> {
    let mut disclosed_terms = BTreeMap::<usize, Fr>::new();
    let mut equivs = HashMap::<NamedOrBlankNode, Vec<(usize, usize)>>::new();

    let DisclosedVerifiableCredential {
        document: disclosed_document,
        proof: disclosed_proof,
    } = disclosed_vc_triples;

    for (j, disclosed_triple) in disclosed_document {
        let subject_index = 3 * j;
        build_disclosed_terms(
            disclosed_triple,
            subject_index,
            vc_index,
            &mut disclosed_terms,
            &mut equivs,
        )?;
    }

    let delimiter_index = disclosed_document.len() * 3;
    let proof_index = delimiter_index + 1;
    let delimiter = get_delimiter()?;
    disclosed_terms.insert(delimiter_index, delimiter);

    for (j, disclosed_triple) in disclosed_proof {
        let subject_index = 3 * j + proof_index;
        build_disclosed_terms(
            disclosed_triple,
            subject_index,
            vc_index,
            &mut disclosed_terms,
            &mut equivs,
        )?;
    }
    Ok(DisclosedTerms {
        disclosed: disclosed_terms,
        equivs,
        term_count: (disclosed_document.len() + disclosed_proof.len()) * 3 + 1,
    })
}

fn build_disclosed_terms(
    disclosed_triple: &Option<Triple>,
    subject_index: usize,
    vc_index: usize,
    disclosed_terms: &mut BTreeMap<usize, Fr>,
    equivs: &mut HashMap<NamedOrBlankNode, Vec<(usize, usize)>>,
) -> Result<(), RDFProofsError> {
    let predicate_index = subject_index + 1;
    let object_index = subject_index + 2;

    let hasher = get_hasher();

    match disclosed_triple {
        Some(triple) => {
            match &triple.subject {
                Subject::BlankNode(b) => {
                    equivs
                        .entry(NamedOrBlankNode::BlankNode(b.clone().into()))
                        .or_default()
                        .push((vc_index, subject_index));
                }
                Subject::NamedNode(n) if is_nym(n) => {
                    equivs
                        .entry(NamedOrBlankNode::NamedNode(n.clone().into()))
                        .or_default()
                        .push((vc_index, subject_index));
                }
                Subject::NamedNode(n) => {
                    let subject_fr = hash_term_to_field(n.into(), &hasher)?;
                    disclosed_terms.insert(subject_index, subject_fr);
                }
                #[cfg(feature = "rdf-star")]
                Subject::Triple(_) => return Err(RDFProofsError::RDFStarUnsupported),
            };

            if is_nym(&triple.predicate) {
                equivs
                    .entry(NamedOrBlankNode::NamedNode(triple.predicate.clone().into()))
                    .or_default()
                    .push((vc_index, predicate_index));
            } else {
                let predicate_fr = hash_term_to_field((&triple.predicate).into(), &hasher)?;
                disclosed_terms.insert(predicate_index, predicate_fr);
            };

            match &triple.object {
                Term::BlankNode(b) => {
                    equivs
                        .entry(NamedOrBlankNode::BlankNode(b.clone().into()))
                        .or_default()
                        .push((vc_index, object_index));
                }
                Term::NamedNode(n) if is_nym(n) => {
                    equivs
                        .entry(NamedOrBlankNode::NamedNode(n.clone().into()))
                        .or_default()
                        .push((vc_index, object_index));
                }
                Term::NamedNode(n) => {
                    let object_fr = hash_term_to_field(n.into(), &hasher)?;
                    disclosed_terms.insert(object_index, object_fr);
                }
                Term::Literal(v) => {
                    let object_fr = hash_term_to_field(v.into(), &hasher)?;
                    disclosed_terms.insert(object_index, object_fr);
                }
                #[cfg(feature = "rdf-star")]
                Term::Triple(_) => return Err(RDFProofsError::DeriveProofValue),
            };
        }

        None => {}
    };
    Ok(())
}

#[derive(Debug)]
struct DisclosedAndUndisclosedTerms {
    disclosed: BTreeMap<usize, Fr>,
    undisclosed: BTreeMap<usize, Fr>,
    equivs: HashMap<NamedOrBlankNode, Vec<(usize, usize)>>,
    term_count: usize,
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
        term_count: (disclosed_document.len() + disclosed_proof.len()) * 3 + 1,
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
                Subject::Triple(_) => return Err(RDFProofsError::RDFStarUnsupported),
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
                Term::Triple(_) => return Err(RDFProofsError::RDFStarUnsupported),
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
        proof::{derive_proof, verify_proof, VcWithDisclosed},
        tests::{
            get_dataset_from_nquads_str, get_deanon_map, get_graph_from_ntriples_str,
            DOCUMENT_LOADER_NTRIPLES,
        },
        vc::VerifiableCredential,
    };
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn derive_and_verify_proof() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed
        let document_loader: DocumentLoader =
            get_graph_from_ntriples_str(DOCUMENT_LOADER_NTRIPLES).into();

        let vc_ntriples_1 = r#"
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
        let vc_proof_ntriples_1 = r#"
_:6b92db <https://w3id.org/security#proofValue> "uhzr5tCpvFA-bebnJZBpUi2mkWStLGmZJm-c6crfIjUsYTbpNywgXUfbaOtD84V-UnHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
_:6b92db <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:6b92db <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:6b92db <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:6b92db <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:6b92db <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
"#;
        let vc_ntriples_2 = r#"
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
        let vc_proof_ntriples_2 = r#"
_:wTnTxH <https://w3id.org/security#proofValue> "usjQI4FuaD8udL2e5Rhvf4J4L0IOjmXT7Q3E40FXnIG-GQ6GMJkUuLv5tU1gJjW42nHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
_:wTnTxH <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:wTnTxH <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:wTnTxH <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:wTnTxH <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:wTnTxH <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> .
"#;
        let disclosed_vc_ntriples_1 = r#"
_:e0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
_:e0 <http://example.org/vocab/isPatientOf> _:a91b3e .
_:a91b3e <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
_:a91b3e <http://example.org/vocab/vaccine> _:e1 .
_:e2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
_:e2 <https://www.w3.org/2018/credentials#credentialSubject> _:e0 .
_:e2 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
_:e2 <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:e2 <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
"#;
        let disclosed_vc_proof_ntriples_1 = r#"
_:6b92db <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:6b92db <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:6b92db <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:6b92db <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:6b92db <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
"#;
        let disclosed_vc_ntriples_2 = r#"
_:e1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccine> .
_:e1 <http://schema.org/status> "active" .
_:e3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
_:e3 <https://www.w3.org/2018/credentials#credentialSubject> _:e1 .
_:e3 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer3> .
_:e3 <https://www.w3.org/2018/credentials#issuanceDate> "2020-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:e3 <https://www.w3.org/2018/credentials#expirationDate> "2023-12-31T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
"#;
        let disclosed_vc_proof_ntriples_2 = r#"
_:wTnTxH <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:wTnTxH <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:wTnTxH <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:wTnTxH <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:wTnTxH <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> .
"#;
        let deanon_map = get_deanon_map(vec![
            ("e0", "did:example:john"),
            ("e1", "http://example.org/vaccine/a"),
            ("e2", "http://example.org/vcred/00"),
            ("e3", "http://example.org/vicred/a"),
        ]);

        let vc_doc_1 = get_graph_from_ntriples_str(vc_ntriples_1);
        let vc_proof_1 = get_graph_from_ntriples_str(vc_proof_ntriples_1);
        let vc_1 = VerifiableCredential::new(vc_doc_1, vc_proof_1);

        let disclosed_vc_doc_1 = get_graph_from_ntriples_str(disclosed_vc_ntriples_1);
        let disclosed_vc_proof_1 = get_graph_from_ntriples_str(disclosed_vc_proof_ntriples_1);
        let disclosed_1 = VerifiableCredential::new(disclosed_vc_doc_1, disclosed_vc_proof_1);

        let vc_doc_2 = get_graph_from_ntriples_str(vc_ntriples_2);
        let vc_proof_2 = get_graph_from_ntriples_str(vc_proof_ntriples_2);
        let vc_2 = VerifiableCredential::new(vc_doc_2, vc_proof_2);

        let disclosed_vc_doc_2 = get_graph_from_ntriples_str(disclosed_vc_ntriples_2);
        let disclosed_vc_proof_2 = get_graph_from_ntriples_str(disclosed_vc_proof_ntriples_2);
        let disclosed_2 = VerifiableCredential::new(disclosed_vc_doc_2, disclosed_vc_proof_2);

        let vc_with_disclosed_1 = VcWithDisclosed::new(vc_1, disclosed_1);
        let vc_with_disclosed_2 = VcWithDisclosed::new(vc_2, disclosed_2);
        let vcs = vec![vc_with_disclosed_1, vc_with_disclosed_2];
        let nonce = b"abcde";
        let derived_proof =
            derive_proof(&mut rng, &vcs, &deanon_map, Some(nonce), &document_loader).unwrap();
        println!("derived_proof: {}", rdf_canon::serialize(&derived_proof));

        let verified = verify_proof(&mut rng, &derived_proof, Some(nonce), &document_loader);
        assert!(verified.is_ok(), "{:?}", verified)
    }

    #[test]
    fn verify_proof_simple() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed
        let document_loader: DocumentLoader =
            get_graph_from_ntriples_str(DOCUMENT_LOADER_NTRIPLES).into();

        let vp_nquads = r#"
_:c14n1 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n11 .
_:c14n1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n11 .
_:c14n1 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" _:c14n11 .
_:c14n1 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n11 .
_:c14n1 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> _:c14n11 .
_:c14n10 <http://example.org/vocab/vaccine> _:c14n5 _:c14n4 .
_:c14n10 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> _:c14n4 .
_:c14n12 <http://purl.org/dc/terms/created> "2023-08-16T03:12:49.668550444Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n8 .
_:c14n12 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n8 .
_:c14n12 <https://w3id.org/security#cryptosuite> "bbs-termwise-proof-2023" _:c14n8 .
_:c14n12 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n8 .
_:c14n12 <https://w3id.org/security#proofValue> "uomVwcm9vZlkJGgIAAAAAAAAAAILzpesgeNjAWzelqJOdlEF4OyouKLi0QyZsftUPCdCsgg4ydsvcOJUbk9cJFNUQZrKNOFs9CP0qHdR_QbYZvhx804iCnnQLZ_Kg0Z7V8Y0pNPgffwtcI8_62f5Nm4K7aaRnLRqEMi_Na4_IRoEPea33lAnbmO2ohj_ogmTVk_G1qKHQuKnRvXnANmpjPHiLSIjVnazDxU7GARWkXoBZiTWjT92XkNVHm9_IdX3qin1Z6bdaYyMEaxCCso5jx1FKzwIAAAAAAAAADMpPluiMSFTtkKtzAP7VLPqOCDMNQmIeO5wms4haGxNiEj_FtTwxi607tO_3MlsJ7G-MAqgiTmvHP6sw-I1QDJCi08G0IRs6xCqI8PDoolZoI1z0zraLVpe9R1WXNPMKmzEQ-zD_KrtyX3ydKl8Ptx8AAAAAAAAAFHTUF8bbWiCR7CLE0Ky3Fi4VfQhz1SgCagyJhVih_klev2vGSmuWDW34T3mitRqqGI9fuv6gjvUmukSBX7TQKdUOtdpfqHZtjLGSoCJ774sfolMKCbtNfm8XJU27Xvtb-8hzv7YRI9YCrtlMzWMGhxeN8KbX-ZiQMU3DUzIT7GysV8lxr12r4CGvVYspGEE4YkRlwXWEugmpsFSV-aVrEN0OUQ7U5L0TsNfp9FDnKVfMg2r_XIhFdAM2UD8VFpVNVAHMqjQnkAmQkuW94SO5oOMPOhT6zCnSpJZeL7InRDzVDrXaX6h2bYyxkqAie--LH6JTCgm7TX5vFyVNu177Wy2UIefOpxbMsC9C4_ZlfUW6fcxzn2yrLA3VjjeDf-xPLZQh586nFsywL0Lj9mV9Rbp9zHOfbKssDdWON4N_7E_VDrXaX6h2bYyxkqAie--LH6JTCgm7TX5vFyVNu177Wy2UIefOpxbMsC9C4_ZlfUW6fcxzn2yrLA3VjjeDf-xPLZQh586nFsywL0Lj9mV9Rbp9zHOfbKssDdWON4N_7E8tlCHnzqcWzLAvQuP2ZX1Fun3Mc59sqywN1Y43g3_sT71Wld_dO1Ph0jjjrkmQJIDdB80VogKnSHdInKFC0rtqDe1EPR6qzxxyLVEes4ys-OF2xVIjSQ2eM2QJe4Y9Vmmz_pOAcM2hWLvY0nO7UJi3M1XLkzmlLbGQBDoR28icEQDgForj-ZjE5_6muJ0f4Xlio8CW8OOgBGmYvVO4I48lL8C0Cm5GkA-4eRqzpl63BlP4_19K-G_v9ui7RU0bghDdrwvwrTcNNckdJg-T3oGL5w6rIdXRnjf7KDw16OszcvvIc7-2ESPWAq7ZTM1jBocXjfCm1_mYkDFNw1MyE-xsaT4CInAfZpLPFP6_ZJ8JabjyJt8u2RtLkBQWucxUjFiLoxJVJNIJZuUd9N4CNIRpCivkZhH0dDumSOIyUZpRP-2qHctcNdtDtbotypp17Vqqi3L3u4w_5aq8A5MWI0kZaT6eI-KdnePqpF5Uu8Rg8ykme6-j5Uf9TFgBAwrrvUf7yHO_thEj1gKu2UzNYwaHF43wptf5mJAxTcNTMhPsbJ-weENC72FgB4rZvRNKluCpua5CHs3PhndXyJTO-78In7B4Q0LvYWAHitm9E0qW4Km5rkIezc-Gd1fIlM77vwifsHhDQu9hYAeK2b0TSpbgqbmuQh7Nz4Z3V8iUzvu_CJ-weENC72FgB4rZvRNKluCpua5CHs3PhndXyJTO-78In7B4Q0LvYWAHitm9E0qW4Km5rkIezc-Gd1fIlM77vwgAp96NoMD4L_PNjc4amwG_T9khjcCiJ3f6wBGo2pDpthmhppfpnnUMpDgY0Z4TWSY-rPvNt6bWHuZ22YGQPqhcedEH-s4MzcCnOw2x2khdjk1ZNJmXjDtRBBp00ZouIbr-g08AO0EeEgmIYN4NExm3zaD1LIdRyT4qaBdtjP0Cnp_UXu6k0oG75k-2DWWpIxWVkI6WcaArlo4u7nnIEbsks0s9vqyhertZ7NahIDTksKYbJxQ9ervfBQG30ZEMLdegAgAAAAAAAADhRIXAJgSyFo-bMFjBOp-l7taq8s2bBTajaRHfYCOvVu_SKea1ghAyYJ2FoTdimcmYYj-WfLdD3McyT63UITNWsXn64FxlTuqf5tQh-Yyadly4qb3lafQB7-_WfoT_K01X6klrgVp2Mc7np4_bmcMcFQAAAAAAAAC2zYWf4D9h1zvRRH_AeLBCCwoQb4slS1ACAxYG533-YSo1_1pC3IxyHS-tWxI-_VQoExa9z50QElsMmELjQn04WFi2_kW2slPL4gkyk3LgSUNl-pQmZdqiNxABuw3VLWOoSSn1n1GC2Q1lW9Zi4qTnOEVWqc3Bt-SHZP4CYeCII_6slx1VaIACRCeSnwrwP5mQga5jUS7DgCGyn-vzqZYxN8pOdAyrojbWZex6w2WWklTrP4pGLstSB9yGv9DdWB9MmpD2lWq4Tb4yMeeoVPtfsmnuU3I4ajPd3q4VWiyQGWiUVt91u6ab_a4_wk_Wl_cFiLoP-LDa5W_cL9oMJGhTaT4CInAfZpLPFP6_ZJ8JabjyJt8u2RtLkBQWucxUjFhpPgIicB9mks8U_r9knwlpuPIm3y7ZG0uQFBa5zFSMWBdxSyAWDqeayQdq9cJXx7HgAp_L7ZjNnwb88H7357NKF3FLIBYOp5rJB2r1wlfHseACn8vtmM2fBvzwfvfns0ppPgIicB9mks8U_r9knwlpuPIm3y7ZG0uQFBa5zFSMWBdxSyAWDqeayQdq9cJXx7HgAp_L7ZjNnwb88H7357NKF3FLIBYOp5rJB2r1wlfHseACn8vtmM2fBvzwfvfns0oXcUsgFg6nmskHavXCV8ex4AKfy-2YzZ8G_PB-9-ezSqDjEQaYgzNsg-fYggN4G1Ldl8gDUfgb2RXxG63l8qwdoOMRBpiDM2yD59iCA3gbUt2XyANR-BvZFfEbreXyrB2g4xEGmIMzbIPn2IIDeBtS3ZfIA1H4G9kV8Rut5fKsHaDjEQaYgzNsg-fYggN4G1Ldl8gDUfgb2RXxG63l8qwdoOMRBpiDM2yD59iCA3gbUt2XyANR-BvZFfEbreXyrB0BBQAAAAAAAABhYmNkZQAAaWluZGV4X21hcIKkYTGJCgwDBAUGBwACYTINYTOFAAECAwRhNAWkYTGHAgMEBQYHCGEyCWEzhQABAgMEYTQF"^^<https://w3id.org/security#multibase> _:c14n8 .
_:c14n13 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:c14n4 .
_:c14n13 <https://w3id.org/security#proof> _:c14n11 _:c14n4 .
_:c14n13 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n6 _:c14n4 .
_:c14n13 <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n4 .
_:c14n13 <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n4 .
_:c14n13 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> _:c14n4 .
_:c14n2 <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n0 .
_:c14n2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n0 .
_:c14n2 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" _:c14n0 .
_:c14n2 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n0 .
_:c14n2 <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> _:c14n0 .
_:c14n3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiablePresentation> .
_:c14n3 <https://w3id.org/security#proof> _:c14n8 .
_:c14n3 <https://www.w3.org/2018/credentials#verifiableCredential> _:c14n4 .
_:c14n3 <https://www.w3.org/2018/credentials#verifiableCredential> _:c14n7 .
_:c14n5 <http://schema.org/status> "active" _:c14n7 .
_:c14n5 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccine> _:c14n7 .
_:c14n6 <http://example.org/vocab/isPatientOf> _:c14n10 _:c14n4 .
_:c14n6 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> _:c14n4 .
_:c14n9 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:c14n7 .
_:c14n9 <https://w3id.org/security#proof> _:c14n0 _:c14n7 .
_:c14n9 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n5 _:c14n7 .
_:c14n9 <https://www.w3.org/2018/credentials#expirationDate> "2023-12-31T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n7 .
_:c14n9 <https://www.w3.org/2018/credentials#issuanceDate> "2020-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n7 .
_:c14n9 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer3> _:c14n7 .
"#;
        let vp = get_dataset_from_nquads_str(vp_nquads);
        let nonce = b"abcde";
        let verified = verify_proof(&mut rng, &vp, Some(nonce), &document_loader);
        assert!(verified.is_ok(), "{:?}", verified)
    }

    #[test]
    fn derive_invalid_vc() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed
        let document_loader: DocumentLoader =
            get_graph_from_ntriples_str(DOCUMENT_LOADER_NTRIPLES).into();

        let vc_ntriples = r#"
<did:example:john> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
<did:example:john> <http://schema.org/name> "**********************************" .  # modified
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
_:6b92db <https://w3id.org/security#proofValue> "uhzr5tCpvFA-bebnJZBpUi2mkWStLGmZJm-c6crfIjUsYTbpNywgXUfbaOtD84V-UnHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
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
_:e2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
_:e2 <https://www.w3.org/2018/credentials#credentialSubject> _:e0 .
_:e2 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
_:e2 <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:e2 <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
"#;
        let disclosed_vc_proof_ntriples = r#"
_:6b92db <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:6b92db <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:6b92db <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:6b92db <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:6b92db <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
"#;
        let deanon_map = get_deanon_map(vec![
            ("e0", "did:example:john"),
            ("e1", "http://example.org/vaccine/a"),
            ("e2", "http://example.org/vcred/00"),
        ]);

        let vc_doc = get_graph_from_ntriples_str(vc_ntriples);
        let vc_proof = get_graph_from_ntriples_str(vc_proof_ntriples);
        let vc = VerifiableCredential::new(vc_doc, vc_proof);

        let disclosed_vc_doc = get_graph_from_ntriples_str(disclosed_vc_ntriples);
        let disclosed_vc_proof = get_graph_from_ntriples_str(disclosed_vc_proof_ntriples);
        let disclosed = VerifiableCredential::new(disclosed_vc_doc, disclosed_vc_proof);

        let vc_with_disclosed = VcWithDisclosed::new(vc, disclosed);
        let vcs = vec![vc_with_disclosed];
        let nonce = b"abcde";
        let derived_proof =
            derive_proof(&mut rng, &vcs, &deanon_map, Some(nonce), &document_loader);
        assert!(matches!(
            derived_proof,
            Err(RDFProofsError::BBSPlus(
                bbs_plus::prelude::BBSPlusError::InvalidSignature
            ))
        ))
    }
}
