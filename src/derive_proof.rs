use super::constants::CRYPTOSUITE_PROOF;
use crate::{
    common::{
        canonicalize_graph, decompose_vp, get_delimiter, get_graph_from_ntriples, get_hasher,
        get_vc_from_ntriples, hash_term_to_field, is_nym, randomize_bnodes, reorder_vc_triples,
        BBSPlusHash, BBSPlusPublicKey, BBSPlusSignature, Fr, PoKBBSPlusStmt, PoKBBSPlusWit, Proof,
        ProofWithIndexMap, StatementIndexMap, Statements,
    },
    context::{
        ASSERTION_METHOD, CHALLENGE, CREATED, CRYPTOSUITE, DATA_INTEGRITY_PROOF, MULTIBASE, PROOF,
        PROOF_PURPOSE, PROOF_VALUE, VERIFIABLE_CREDENTIAL, VERIFIABLE_CREDENTIAL_TYPE,
        VERIFIABLE_PRESENTATION_TYPE, VERIFICATION_METHOD,
    },
    error::RDFProofsError,
    key_gen::generate_params,
    key_graph::KeyGraph,
    ordered_triple::{OrderedNamedOrBlankNode, OrderedVerifiableCredentialGraphViews},
    signature::verify,
    vc::{
        DisclosedVerifiableCredential, VcPair, VerifiableCredential, VerifiableCredentialTriples,
        VpGraphs,
    },
    VcPairString,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
use chrono::offset::Utc;
use multibase::Base;
use oxrdf::{
    vocab::{rdf::TYPE, xsd},
    BlankNode, Dataset, Graph, GraphNameRef, Literal, LiteralRef, NamedNode, NamedOrBlankNode,
    Quad, QuadRef, Subject, Term, TermRef, Triple,
};
use proof_system::{
    prelude::{EqualWitnesses, MetaStatements},
    proof_spec::ProofSpec,
    witness::Witnesses,
};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashMap};

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

    // split VC pairs into original VCs and disclosed VCs
    let (original_vcs, disclosed_vcs): (Vec<_>, Vec<_>) = randomized_vc_pairs
        .into_iter()
        .map(
            |VcPair {
                 original,
                 disclosed,
             }| (original, disclosed),
        )
        .unzip();

    // build VP draft (= canonicalized VP without proofValue) based on disclosed VCs
    let (vp_draft, vp_draft_bnode_map, vc_document_graph_names) = build_vp(disclosed_vcs, &nonce)?;

    // decompose VP draft into graphs
    let VpGraphs {
        metadata: _vp_metadata_graph,
        proof: vp_proof_graph,
        proof_graph_name: vp_proof_graph_name,
        disclosed_vcs: canonicalized_disclosed_vc_graphs,
        filters: _filters_graph,
    } = decompose_vp(&vp_draft)?;

    // extract `proofValue`s from original VCs
    let (original_vcs_without_proof_value, vc_proof_values): (Vec<_>, Vec<_>) = original_vcs
        .iter()
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
        canonicalize_vcs(&original_vcs_without_proof_value)?;

    for v in &canonicalized_original_vcs {
        println!("canonicalized_original_vcs: {}", v);
    }
    println!("original vcs bnode map: {:#?}", original_vcs_bnode_map);

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

    println!("canonicalized original VC (sorted):");
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
    println!("canonicalized disclosed VC (sorted):");
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

pub fn derive_proof_string<R: RngCore>(
    rng: &mut R,
    vc_pairs: &Vec<VcPairString>,
    deanon_map: &HashMap<String, String>,
    nonce: Option<&str>,
    key_graph: &str,
) -> Result<String, RDFProofsError> {
    // construct input for `derive_proof` from string-based input
    let vc_pairs = vc_pairs
        .iter()
        .map(|pair| {
            Ok(VcPair::new(
                get_vc_from_ntriples(&pair.original_document, &pair.original_proof)?,
                get_vc_from_ntriples(&pair.disclosed_document, &pair.disclosed_proof)?,
            ))
        })
        .collect::<Result<Vec<_>, RDFProofsError>>()?;
    let deanon_map = get_deanon_map_from_string(deanon_map)?;
    let key_graph = get_graph_from_ntriples(key_graph)?.into();

    let proof_dataset = derive_proof(rng, &vc_pairs, &deanon_map, nonce, &key_graph)?;

    Ok(rdf_canon::serialize(&proof_dataset))
}

pub(crate) fn get_deanon_map_from_string(
    deanon_map_string: &HashMap<String, String>,
) -> Result<HashMap<NamedOrBlankNode, Term>, RDFProofsError> {
    let re_iri = Regex::new(r"^<([^>]+)>$")?;
    let re_blank_node = Regex::new(r"^_:(.+)$")?;
    let re_simple_literal = Regex::new(r#"^"([^"]+)"$"#)?;
    let re_typed_literal = Regex::new(r#"^"([^"]+)"\^\^<([^>]+)>$"#)?;
    let re_literal_with_langtag = Regex::new(r#"^"([^"]+)"@(.+)$"#)?;

    deanon_map_string
        .iter()
        .map(|(k, v)| {
            let key: NamedOrBlankNode = if let Some(caps) = re_blank_node.captures(k) {
                Ok(BlankNode::new_unchecked(&caps[1]).into())
            } else if let Some(caps) = re_iri.captures(k) {
                Ok(NamedNode::new_unchecked(&caps[1]).into())
            } else {
                Err(RDFProofsError::InvalidDeanonMapFormat(k.to_string()))
            }?;

            let value: Term = if let Some(caps) = re_iri.captures(v) {
                Ok(NamedNode::new_unchecked(&caps[1]).into())
            } else if let Some(caps) = re_simple_literal.captures(v) {
                Ok(Literal::new_simple_literal(&caps[1]).into())
            } else if let Some(caps) = re_typed_literal.captures(v) {
                Ok(Literal::new_typed_literal(&caps[1], NamedNode::new_unchecked(&caps[2])).into())
            } else if let Some(caps) = re_literal_with_langtag.captures(v) {
                Ok(Literal::new_language_tagged_literal(&caps[1], &caps[2])?.into())
            } else {
                Err(RDFProofsError::InvalidDeanonMapFormat(v.to_string()))
            }?;

            Ok((key, value))
        })
        .collect()
}

fn get_public_keys(
    proof_graph: &Graph,
    key_graph: &KeyGraph,
) -> Result<BBSPlusPublicKey, RDFProofsError> {
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
            let (canonicalized_document, document_bnode_map) = canonicalize_graph(document)?;
            let (canonicalized_proof, proof_bnode_map) = canonicalize_graph(proof)?;
            for (k, v) in &document_bnode_map {
                if bnode_map.contains_key(k) {
                    return Err(RDFProofsError::BlankNodeCollision);
                } else {
                    bnode_map.insert(k.to_string(), v.to_string());
                }
            }
            for (k, v) in &proof_bnode_map {
                if bnode_map.contains_key(k) {
                    return Err(RDFProofsError::BlankNodeCollision);
                } else {
                    bnode_map.insert(k.to_string(), v.to_string());
                }
            }

            Ok(VerifiableCredential::new(
                canonicalized_document,
                canonicalized_proof,
            ))
        })
        .collect::<Result<Vec<_>, RDFProofsError>>()?;
    Ok((canonicalized_vcs, bnode_map))
}

fn build_vp(
    disclosed_vcs: Vec<VerifiableCredential>,
    nonce: &Option<&str>,
) -> Result<(Dataset, HashMap<String, String>, Vec<BlankNode>), RDFProofsError> {
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

    // convert disclosed VC graphs (triples) into disclosed VC dataset (quads)
    let mut disclosed_vc_document_graph_names = Vec::with_capacity(disclosed_vcs.len());
    let disclosed_vc_quads = disclosed_vcs
        .iter()
        .map(
            |VerifiableCredential {
                 document: disclosed_vc_document,
                 proof: disclosed_vc_proof,
             }| {
                // generate random blank nodes as graph names
                let disclosed_vc_document_graph_name = BlankNode::default();
                let disclosed_vc_proof_graph_name = BlankNode::default();

                disclosed_vc_document_graph_names.push(disclosed_vc_document_graph_name.clone());

                let disclosed_vc_document_id = disclosed_vc_document
                    .subject_for_predicate_object(TYPE, VERIFIABLE_CREDENTIAL_TYPE)
                    .ok_or(RDFProofsError::VCWithoutVCType)?;

                let mut disclosed_vc_document_quads: Vec<Quad> = disclosed_vc_document
                    .iter()
                    .map(|t| {
                        t.into_owned()
                            .in_graph(disclosed_vc_document_graph_name.clone())
                    })
                    .collect();

                // add `proof` link from VC document to VC proof graph
                disclosed_vc_document_quads.push(Quad::new(
                    disclosed_vc_document_id,
                    PROOF,
                    disclosed_vc_proof_graph_name.clone(),
                    disclosed_vc_document_graph_name.clone(),
                ));

                let mut proof_quads: Vec<Quad> = disclosed_vc_proof
                    .iter()
                    .filter(|t| t.predicate != PROOF_VALUE) // remove `proofValue` if exists
                    .map(|t| {
                        t.into_owned()
                            .in_graph(disclosed_vc_proof_graph_name.clone())
                    })
                    .collect();
                disclosed_vc_document_quads.append(&mut proof_quads);

                Ok((
                    disclosed_vc_document_graph_name,
                    disclosed_vc_document_quads,
                ))
            },
        )
        .collect::<Result<Vec<_>, RDFProofsError>>()?;

    // merge VC dataset into VP draft
    for (disclosed_vc_graph_name, disclosed_vc_quad) in disclosed_vc_quads {
        vp.insert(QuadRef::new(
            &vp_id,
            VERIFIABLE_CREDENTIAL,
            &disclosed_vc_graph_name,
            GraphNameRef::DefaultGraph,
        ));
        vp.extend(disclosed_vc_quad);
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
        disclosed_vc_document_graph_names,
    ))
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
    let mut ordered_original_vcs = BTreeMap::new();
    let mut ordered_proof_values = BTreeMap::new();

    for k in canonicalized_disclosed_vc_graphs.keys() {
        let canonicalized_disclosed_vc_graph_name: &GraphNameRef = k.into();
        let original_vc_graph_name = match canonicalized_disclosed_vc_graph_name {
            GraphNameRef::BlankNode(n) => match extended_deanon_map.get(&(*n).into()) {
                Some(Term::BlankNode(n)) => Ok(n),
                _ => Err(RDFProofsError::Other("invalid VC graph name".to_string())),
            },
            _ => Err(RDFProofsError::Other("invalid VC graph name".to_string())),
        }?;
        let original_index = vc_document_graph_names
            .iter()
            .position(|v| v == original_vc_graph_name)
            .ok_or(RDFProofsError::Other("invalid VC index".to_string()))?;
        let original_vc = canonicalized_original_vcs
            .get(original_index)
            .ok_or(RDFProofsError::Other("invalid VC index".to_string()))?;
        let proof_value = proof_values
            .get(original_index)
            .ok_or(RDFProofsError::Other(
                "invalid proof value index".to_string(),
            ))?;
        ordered_original_vcs.insert(k.clone(), original_vc);
        ordered_proof_values.insert(k.clone(), proof_value.to_owned());
    }

    // assert the keys of two VC graphs are equivalent
    if !ordered_original_vcs
        .keys()
        .eq(canonicalized_disclosed_vc_graphs.keys())
    {
        return Err(RDFProofsError::Other(
            "the graph names of original and disclosed VC must be equivalent".to_string(),
        ));
    }

    // convert to Vecs
    let original_vc_vec = ordered_original_vcs
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
                Ok(StatementIndexMap::new(
                    document_map,
                    document_len,
                    proof_map,
                    proof_len,
                ))
            },
        )
        .collect::<Result<Vec<_>, RDFProofsError>>()?;

    Ok(index_map)
}

fn derive_proof_value<R: RngCore>(
    rng: &mut R,
    original_vc_triples: Vec<VerifiableCredentialTriples>,
    disclosed_vc_triples: Vec<VerifiableCredentialTriples>,
    public_keys: Vec<BBSPlusPublicKey>,
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

    let term_counts = disclosed_and_undisclosed_terms
        .iter()
        .map(|t| {
            t.term_count
                .try_into()
                .map_err(|_| RDFProofsError::MessageSizeOverflow)
        })
        .collect::<Result<Vec<u32>, _>>()?;

    let params_and_pks = term_counts
        .iter()
        .zip(public_keys)
        .map(|(t, pk)| (generate_params(*t), pk));

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
    let mut statements = Statements::new();
    for (DisclosedAndUndisclosedTerms { disclosed, .. }, (params, public_key)) in
        disclosed_and_undisclosed_terms.iter().zip(params_and_pks)
    {
        statements.add(PoKBBSPlusStmt::new_statement_from_params(
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
        let signature = BBSPlusSignature::deserialize_compressed(&*proof_value_bytes)?;
        witnesses.add(PoKBBSPlusWit::new_as_witness(
            signature,
            undisclosed.clone(),
        ));
    }
    println!("witnesses:\n{:#?}\n", witnesses);

    // build proof
    let proof = Proof::new::<R, BBSPlusHash>(
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
    proof: Proof,
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
