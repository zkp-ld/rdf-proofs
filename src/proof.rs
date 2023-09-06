use super::constants::{CRYPTOSUITE_PROOF, NYM_IRI_PREFIX};
use crate::{
    common::{get_delimiter, get_hasher, hash_term_to_field, randomize_bnodes, Fr, ProofG1},
    context::{
        ASSERTION_METHOD, CHALLENGE, CREATED, CRYPTOSUITE, DATA_INTEGRITY_PROOF, FILTER, MULTIBASE,
        PROOF, PROOF_PURPOSE, PROOF_VALUE, VERIFIABLE_CREDENTIAL, VERIFIABLE_CREDENTIAL_TYPE,
        VERIFIABLE_PRESENTATION_TYPE, VERIFICATION_METHOD,
    },
    error::RDFProofsError,
    key_gen::generate_params,
    key_graph::KeyGraph,
    ordered_triple::{
        OrderedGraphNameRef, OrderedGraphViews, OrderedNamedOrBlankNode,
        OrderedVerifiableCredentialGraphViews,
    },
    signature::verify,
    vc::{
        DisclosedVerifiableCredential, VcPair, VerifiableCredential, VerifiableCredentialTriples,
        VerifiableCredentialView, VpGraphs,
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
    Quad, QuadRef, Subject, Term, TermRef, Triple,
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

/// derive VP from VCs, disclosed VCs, and deanonymization map
pub fn derive_proof<R: RngCore>(
    rng: &mut R,
    vc_pairs: &Vec<VcPair>,
    deanon_map: &HashMap<NamedOrBlankNode, Term>,
    nonce: Option<&str>,
    key_graph: &KeyGraph,
) -> Result<Dataset, RDFProofsError> {
    for vc in vc_pairs {
        println!("{}", vc.to_string());
    }
    println!("deanon map:\n{:#?}\n", deanon_map);

    // VCs must not be empty
    if vc_pairs.is_empty() {
        return Err(RDFProofsError::InvalidVCPairs);
    }

    // TODO:
    // check: each disclosed VCs must be the derived subset of corresponding VCs via deanon map

    // get issuer public keys
    let public_keys = vc_pairs
        .iter()
        .map(|VcPair { original: vc, .. }| get_public_keys(&vc.proof, key_graph))
        .collect::<Result<Vec<_>, _>>()?;
    println!("public keys:\n{:#?}\n", public_keys);

    // verify VCs
    vc_pairs
        .iter()
        .map(|VcPair { original: vc, .. }| verify(vc, key_graph))
        .collect::<Result<(), _>>()?;

    // randomize blank node identifiers in VC documents and VC proofs
    // for avoiding identifier collisions among multiple VCs
    let randomized_vc_pairs = vc_pairs
        .iter()
        .map(
            |VcPair {
                 original,
                 disclosed,
             }| {
                let (r_original_document, r_disclosed_document) =
                    randomize_bnodes(&original.document, &disclosed.document);
                let (r_original_proof, r_disclosed_proof) =
                    randomize_bnodes(&original.proof, &disclosed.proof);
                VcPair::new(
                    VerifiableCredential::new(r_original_document, r_original_proof),
                    VerifiableCredential::new(r_disclosed_document, r_disclosed_proof),
                )
            },
        )
        .collect::<Vec<_>>();
    for vc in &randomized_vc_pairs {
        println!("randomized vc: {}", vc.to_string());
    }

    // get disclosed VCs
    let disclosed_vcs = randomized_vc_pairs
        .iter()
        .map(|VcPair { disclosed, .. }| disclosed)
        .collect();

    // build VP draft (= VP without proofValue) based on disclosed VCs
    let (vp_draft, vp_draft_bnode_map, vc_document_graph_names) =
        build_vp_draft(&disclosed_vcs, &nonce)?;

    // decompose VP draft into graphs
    let VpGraphs {
        metadata: _vp_metadata_graph,
        proof: vp_proof_graph,
        proof_graph_name: vp_proof_graph_name,
        disclosed_vcs: canonicalized_disclosed_vc_graphs,
        filters: _filters_graph,
    } = decompose_vp(&vp_draft)?;

    // extract `proofValue`s from original VCs
    let (randomized_original_vcs, vc_proof_values): (Vec<_>, Vec<_>) = randomized_vc_pairs
        .iter()
        .map(|VcPair { original: vc, .. }| vc)
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
    let (canonicalized_original_vcs, original_vcs_bnode_map) =
        canonicalize_vcs(&randomized_original_vcs)?;

    // construct extended deanonymization map
    let extended_deanon_map =
        extend_deanon_map(deanon_map, &vp_draft_bnode_map, &original_vcs_bnode_map)?;
    println!("extended deanon map:");
    for (f, t) in &extended_deanon_map {
        println!("{}: {}", f.to_string(), t.to_string());
    }
    println!("");

    // reorder the original VC graphs and proof values
    // according to the order of canonicalized graph names of disclosed VCs
    let (original_vc_vec, disclosed_vc_vec, vc_proof_values_vec) = reorder_vc_graphs(
        &canonicalized_original_vcs,
        &vc_proof_values,
        &canonicalized_disclosed_vc_graphs,
        &extended_deanon_map,
        &vc_document_graph_names,
    )?;

    println!("canonicalized original VC graphs (sorted):");
    for VerifiableCredentialTriples { document, proof } in &original_vc_vec {
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
    for VerifiableCredentialTriples { document, proof } in &disclosed_vc_vec {
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
    let index_map = gen_index_map(&original_vc_vec, &disclosed_vc_vec, &extended_deanon_map)?;
    println!("index_map:\n{:#?}\n", index_map);

    // derive proof value
    let derived_proof_value = derive_proof_value(
        rng,
        original_vc_vec,
        disclosed_vc_vec,
        public_keys,
        vc_proof_values_vec,
        index_map,
        &vp_draft,
        nonce,
    )?;

    // add derived proof value to VP
    let vp_proof_subject = vp_proof_graph
        .subject_for_predicate_object(TYPE, DATA_INTEGRITY_PROOF)
        .ok_or(RDFProofsError::InvalidVP)?;
    let vp_proof_value_quad = QuadRef::new(
        vp_proof_subject,
        PROOF_VALUE,
        LiteralRef::new_typed_literal(&derived_proof_value, MULTIBASE),
        vp_proof_graph_name,
    );
    let mut canonicalized_vp_quads = vp_draft.into_iter().collect::<Vec<_>>();
    canonicalized_vp_quads.push(vp_proof_value_quad);

    Ok(Dataset::from_iter(canonicalized_vp_quads))
}

/// verify VP
pub fn verify_proof<R: RngCore>(
    rng: &mut R,
    vp: &Dataset,
    nonce: Option<&str>,
    key_graph: &KeyGraph,
) -> Result<(), RDFProofsError> {
    println!("VP:\n{}", rdf_canon::serialize(&vp));

    // decompose VP into graphs to identify VP proof and proof graph name
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

    // drop proof value from VP proof before canonicalization
    // (otherwise it could differ from the prover's canonicalization)
    let vp_without_proof_value = Dataset::from_iter(
        vp.iter()
            .filter(|q| !(q.predicate == PROOF_VALUE && q.graph_name == proof_graph_name)),
    );

    // nonce check
    let get_nonce = || {
        let nonce_in_vp_triple = vp_proof_with_value.triples_for_predicate(CHALLENGE).next();
        if let Some(triple) = nonce_in_vp_triple {
            if let TermRef::Literal(v) = triple.object {
                Ok(Some(v.value()))
            } else {
                Err(RDFProofsError::InvalidChallengeDatatype)
            }
        } else {
            Ok(None)
        }
    };
    match (nonce, get_nonce()?) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(RDFProofsError::MissingChallengeInRequest),
        (Some(_), None) => Err(RDFProofsError::MissingChallengeInVP),
        (Some(given_nonce), Some(nonce_in_vp)) => {
            if given_nonce == nonce_in_vp {
                Ok(())
            } else {
                Err(RDFProofsError::MismatchedChallenge)
            }
        }
    }?;

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
        .map(|(_, vc)| get_public_keys_from_graphview(&vc.proof, key_graph))
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
        nonce.map(|v| v.as_bytes().to_vec()),
        Default::default(),
    )?)
}

fn get_public_keys(
    proof_graph: &Graph,
    key_graph: &KeyGraph,
) -> Result<BBSPublicKeyG2<Bls12_381>, RDFProofsError> {
    let vm_triple = proof_graph
        .triples_for_predicate(VERIFICATION_METHOD)
        .next()
        .ok_or(RDFProofsError::InvalidVerificationMethod)?;
    let vm = match vm_triple.object {
        TermRef::NamedNode(v) => Ok(v),
        _ => Err(RDFProofsError::InvalidVerificationMethodURL),
    }?;
    key_graph.get_public_key(vm)
}

// TODO: to be integrated with `get_public_keys`
fn get_public_keys_from_graphview(
    proof_graph: &GraphView,
    key_graph: &KeyGraph,
) -> Result<BBSPublicKeyG2<Bls12_381>, RDFProofsError> {
    let vm_triple = proof_graph
        .triples_for_predicate(VERIFICATION_METHOD)
        .next()
        .ok_or(RDFProofsError::InvalidVerificationMethod)?;
    let vm = match vm_triple.object {
        TermRef::NamedNode(v) => Ok(v),
        _ => Err(RDFProofsError::InvalidVerificationMethodURL),
    }?;
    key_graph.get_public_key(vm)
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

fn canonicalize_vcs(
    vcs: &Vec<VerifiableCredential>,
) -> Result<(Vec<VerifiableCredential>, HashMap<String, String>), RDFProofsError> {
    let mut bnode_map = HashMap::new();
    let canonicalized_vcs = vcs
        .iter()
        .map(|VerifiableCredential { document, proof }| {
            let document_bnode_map = rdf_canon::issue_graph(&document)?;
            for (k, v) in &document_bnode_map {
                if bnode_map.contains_key(k) {
                    return Err(RDFProofsError::BlankNodeCollision);
                } else {
                    bnode_map.insert(k.to_string(), v.to_string());
                }
            }
            let proof_bnode_map = rdf_canon::issue_graph(&proof)?;
            for (k, v) in &proof_bnode_map {
                if bnode_map.contains_key(k) {
                    return Err(RDFProofsError::BlankNodeCollision);
                } else {
                    bnode_map.insert(k.to_string(), v.to_string());
                }
            }

            let canonicalized_document = rdf_canon::relabel_graph(&document, &document_bnode_map)?;
            let canonicalized_proof = rdf_canon::relabel_graph(&proof, &proof_bnode_map)?;
            Ok(VerifiableCredential::new(
                canonicalized_document,
                canonicalized_proof,
            ))
        })
        .collect::<Result<Vec<_>, RDFProofsError>>()?;
    Ok((canonicalized_vcs, bnode_map))
}

fn build_vp_draft(
    disclosed_vcs: &Vec<&VerifiableCredential>,
    nonce: &Option<&str>,
) -> Result<(Dataset, HashMap<String, String>, Vec<BlankNode>), RDFProofsError> {
    // remove `proofValue` if exists
    let disclosed_vcs: Vec<VerifiableCredential> = disclosed_vcs
        .iter()
        .map(|VerifiableCredential { document, proof }| {
            VerifiableCredential::new(
                // clone document and proof without `proofValue`
                Graph::from_iter(document),
                Graph::from_iter(proof.iter().filter(|t| t.predicate != PROOF_VALUE)),
            )
        })
        .collect();

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
    if let Some(nonce) = nonce {
        vp.insert(QuadRef::new(
            &vp_proof_id,
            CHALLENGE,
            LiteralRef::new_simple_literal(*nonce),
            &vp_proof_graph_id,
        ));
    }

    // convert VC graphs (triples) into VC dataset (quads)
    let mut vc_document_graph_names = Vec::with_capacity(disclosed_vcs.len());
    let vc_quads = disclosed_vcs
        .iter()
        .map(|VerifiableCredential { document, proof }| {
            let document_graph_name = BlankNode::default();
            let proof_graph_name = BlankNode::default();

            vc_document_graph_names.push(document_graph_name.clone());

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

    // merge VC dataset into VP draft
    for (vc_graph_name, vc_quad) in vc_quads {
        vp.insert(QuadRef::new(
            &vp_id,
            VERIFIABLE_CREDENTIAL,
            &vc_graph_name,
            GraphNameRef::DefaultGraph,
        ));
        vp.extend(vc_quad);
    }

    println!("vp draft (before canonicalization):\n{}\n", vp.to_string());

    // canonicalize VP draft
    let canonicalized_vp_bnode_map = rdf_canon::issue(&vp)?;
    let canonicalized_vp = rdf_canon::relabel(&vp, &canonicalized_vp_bnode_map)?;
    println!("VP draft bnode map:\n{:#?}\n", canonicalized_vp_bnode_map);
    println!("VP draft:\n{}", rdf_canon::serialize(&canonicalized_vp));

    Ok((
        canonicalized_vp,
        canonicalized_vp_bnode_map,
        vc_document_graph_names,
    ))
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

fn extend_deanon_map(
    deanon_map: &HashMap<NamedOrBlankNode, Term>,
    vp_draft_bnode_map: &HashMap<String, String>,
    original_vcs_bnode_map: &HashMap<String, String>,
) -> Result<HashMap<NamedOrBlankNode, Term>, RDFProofsError> {
    // blank node -> original term
    let mut res = vp_draft_bnode_map
        .into_iter()
        .map(|(bnid, cnid)| {
            let mapped_bnid = match original_vcs_bnode_map.get(bnid) {
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

    // named node -> original term
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

fn reorder_vc_graphs(
    canonicalized_original_vcs: &Vec<VerifiableCredential>,
    proof_values: &Vec<&str>,
    canonicalized_disclosed_vc_graphs: &OrderedVerifiableCredentialGraphViews,
    extended_deanon_map: &HashMap<NamedOrBlankNode, Term>,
    vc_document_graph_names: &Vec<BlankNode>,
) -> Result<
    (
        Vec<VerifiableCredentialTriples>,
        Vec<VerifiableCredentialTriples>,
        Vec<String>,
    ),
    RDFProofsError,
> {
    let mut ordered_vcs = BTreeMap::new();
    let mut ordered_proof_values = BTreeMap::new();

    for k in canonicalized_disclosed_vc_graphs.keys() {
        let vc_graph_name_c14n: &GraphNameRef = k.into();
        let vc_graph_name = match vc_graph_name_c14n {
            GraphNameRef::BlankNode(n) => match extended_deanon_map.get(&(*n).into()) {
                Some(Term::BlankNode(n)) => Ok(n),
                _ => Err(RDFProofsError::Other("invalid VC graph name".to_string())),
            },
            _ => Err(RDFProofsError::Other("invalid VC graph name".to_string())),
        }?;
        let index = vc_document_graph_names
            .iter()
            .position(|v| v == vc_graph_name)
            .ok_or(RDFProofsError::Other("invalid VC index".to_string()))?;
        let vc = canonicalized_original_vcs
            .get(index)
            .ok_or(RDFProofsError::Other("invalid VC index".to_string()))?;
        let proof_value = proof_values.get(index).ok_or(RDFProofsError::Other(
            "invalid proof value index".to_string(),
        ))?;
        ordered_vcs.insert(k.clone(), vc);
        ordered_proof_values.insert(k.clone(), proof_value.to_owned());
    }

    // assert the keys of two VC graphs are equivalent
    if !ordered_vcs
        .keys()
        .eq(canonicalized_disclosed_vc_graphs.keys())
    {
        return Err(RDFProofsError::Other(
            "gen_index_map: the keys of two VC graphs must be equivalent".to_string(),
        ));
    }

    // convert to Vecs
    let original_vc_vec = ordered_vcs
        .into_iter()
        .map(|(_, v)| v.into())
        .collect::<Vec<VerifiableCredentialTriples>>();
    let disclosed_vc_vec = canonicalized_disclosed_vc_graphs
        .into_iter()
        .map(|(_, v)| v.into())
        .collect::<Vec<VerifiableCredentialTriples>>();
    let vc_proof_values_vec = ordered_proof_values
        .into_iter()
        .map(|(_, v)| v.into())
        .collect::<Vec<_>>();

    Ok((original_vc_vec, disclosed_vc_vec, vc_proof_values_vec))
}

fn gen_index_map(
    original_vc_vec: &Vec<VerifiableCredentialTriples>,
    disclosed_vc_vec: &Vec<VerifiableCredentialTriples>,
    extended_deanon_map: &HashMap<NamedOrBlankNode, Term>,
) -> Result<Vec<StatementIndexMap>, RDFProofsError> {
    let mut disclosed_vc_triples_cloned = (*disclosed_vc_vec).clone();

    // deanonymize each disclosed VC triples, keeping their orders
    for VerifiableCredentialTriples { document, proof } in &mut disclosed_vc_triples_cloned {
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
    for VerifiableCredentialTriples { document, proof } in &disclosed_vc_triples_cloned {
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
    let index_map = disclosed_vc_triples_cloned
        .iter()
        .zip(original_vc_vec)
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
    proof_values: Vec<String>,
    index_map: Vec<StatementIndexMap>,
    canonicalized_vp: &Dataset,
    nonce: Option<&str>,
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
        nonce.map(|v| v.as_bytes().to_vec()), // TODO: consider if it is required as it's already included in `proof_spec.context`
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
        key_graph::KeyGraph,
        proof::{derive_proof, verify_proof, VcPair},
        tests::{
            get_dataset_from_nquads_str, get_deanon_map, get_graph_from_ntriples_str,
            KEY_GRAPH_NTRIPLES,
        },
        vc::VerifiableCredential,
    };
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use oxrdf::{NamedOrBlankNode, Term};
    use std::collections::HashMap;

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

    const VC_PROOF_NTRIPLES_1: &str = r#"
    _:b0 <https://w3id.org/security#proofValue> "utEnCefxSJlHuHFWGuCEqapeOkbNUMcUZfixkTP-eelRRXBCUpSl8wNNxHQqDcVgDnHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
    _:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
    _:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
    _:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
    "#;

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

    fn get_example_deanon_map() -> HashMap<NamedOrBlankNode, Term> {
        get_deanon_map(vec![
            ("e0", "did:example:john", None),
            ("e1", "http://example.org/vaccine/a", None),
            ("e2", "http://example.org/vcred/00", None),
            ("e3", "http://example.org/vicred/a", None),
        ])
    }

    #[test]
    fn derive_and_verify_proof() {
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
    fn verify_proof_simple() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed
        let key_graph: KeyGraph = get_graph_from_ntriples_str(KEY_GRAPH_NTRIPLES).into();

        let vp_nquads = r#"
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
        let vp = get_dataset_from_nquads_str(vp_nquads);
        let nonce = "abcde";
        let verified = verify_proof(&mut rng, &vp, Some(nonce), &key_graph);
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

        let derived_proof = derive_proof(&mut rng, &vcs, &deanon_map, None, &key_graph).unwrap();
        println!("derived_proof: {}", rdf_canon::serialize(&derived_proof));

        let verified = verify_proof(&mut rng, &derived_proof, None, &key_graph);
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
        println!("derived_proof: {}", rdf_canon::serialize(&derived_proof));

        let nonce = "abcde";

        let verified = verify_proof(&mut rng, &derived_proof, Some(nonce), &key_graph);
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
        println!("derived_proof: {}", rdf_canon::serialize(&derived_proof));

        let verified = verify_proof(&mut rng, &derived_proof, None, &key_graph);
        assert!(matches!(
            verified,
            Err(RDFProofsError::MissingChallengeInRequest)
        ))
    }

    #[test]
    fn derive_and_verify_proof_with_hidden_literals() {
        let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed
        let key_graph: KeyGraph = get_graph_from_ntriples_str(KEY_GRAPH_NTRIPLES).into();

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

        let mut deanon_map = get_example_deanon_map();
        let deanon_map_with_hidden_literal = get_deanon_map(vec![
            ("e4", "John Smith", Some("")),
            (
                "e5",
                "2022-01-01T00:00:00Z",
                Some("http://www.w3.org/2001/XMLSchema#dateTime"),
            ),
        ]);
        deanon_map.extend(deanon_map_with_hidden_literal);

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
    fn derive_invalid_vc() {
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
}
