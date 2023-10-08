use crate::{
    common::{
        generate_proof_spec_context, get_dataset_from_nquads, get_delimiter,
        get_graph_from_ntriples, get_hasher, get_term_from_string, hash_term_to_field, is_nym,
        reorder_vc_triples, BBSPlusHash, BBSPlusPublicKey, Fr, PedersenCommitmentStmt,
        PoKBBSPlusStmt, ProofWithIndexMap, Statements, VerifyingKey,
    },
    constants::PPID_PREFIX,
    context::{
        CHALLENGE, CIRCUIT, DOMAIN, HOLDER, PREDICATE, PREDICATE_VAL, PREDICATE_VAR, PRIVATE,
        PROOF_VALUE, PUBLIC, SECRET_COMMITMENT, VERIFIABLE_PRESENTATION_TYPE, VERIFICATION_METHOD,
    },
    error::RDFProofsError,
    key_gen::{generate_params, generate_ppid_base},
    key_graph::KeyGraph,
    multibase_to_ark,
    ordered_triple::OrderedNamedOrBlankNode,
    vc::{DisclosedVerifiableCredential, VerifiableCredentialTriples, VerifiablePresentation},
};
use ark_bls12_381::G1Affine;
use ark_std::{rand::RngCore, One};
use oxrdf::{
    dataset::GraphView,
    vocab::rdf::{FIRST, NIL, REST, TYPE},
    BlankNode, BlankNodeRef, Dataset, NamedNode, NamedOrBlankNode, NamedOrBlankNodeRef, Subject,
    Term, TermRef, Triple,
};
use proof_system::{
    prelude::{EqualWitnesses, MetaStatements},
    proof_spec::ProofSpec,
    statement::r1cs_legogroth16::R1CSCircomVerifier,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Debug)]
struct VerifierPredicateProofStatement {
    pub snark_verifying_key: VerifyingKey,
    pub private: Vec<(String, BlankNode)>,
    pub public: Vec<(String, Term)>,
}

/// verify VP
pub fn verify_proof<R: RngCore>(
    rng: &mut R,
    vp_dataset: &Dataset,
    key_graph: &KeyGraph,
    challenge: Option<&str>,
    domain: Option<&str>,
    snark_verifying_keys: Option<HashMap<NamedNode, VerifyingKey>>,
) -> Result<(), RDFProofsError> {
    let hasher = get_hasher();

    println!("VP:\n{}", rdf_canon::serialize(vp_dataset));

    // decompose VP into graphs
    let vp: VerifiablePresentation = vp_dataset.try_into()?;

    // get proof value
    let proof_value_encoded = vp.get_proof_value()?;

    // drop proof value from VP proof before canonicalization
    // (otherwise it could differ from the prover's canonicalization)
    let vp_without_proof_value = Dataset::from_iter(
        vp_dataset
            .iter()
            .filter(|q| !(q.predicate == PROOF_VALUE && q.graph_name == vp.proof_graph_name)),
    );

    // validate challenge
    match (challenge, vp.get_proof_config_literal(CHALLENGE)?) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(RDFProofsError::MissingChallengeInRequest),
        (Some(_), None) => Err(RDFProofsError::MissingChallengeInVP),
        (Some(given_challenge), Some(challenge_in_vp)) => {
            if given_challenge == challenge_in_vp {
                Ok(())
            } else {
                Err(RDFProofsError::MismatchedChallenge)
            }
        }
    }?;

    // validate domain
    match (domain, vp.get_proof_config_literal(DOMAIN)?) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(RDFProofsError::MissingDomainInRequest),
        (Some(_), None) => Err(RDFProofsError::MissingDomainInVP),
        (Some(given_domain), Some(domain_in_vp)) => {
            if given_domain == domain_in_vp {
                Ok(())
            } else {
                Err(RDFProofsError::MismatchedDomain)
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

    // decompose canonicalized VP into graphs
    let VerifiablePresentation {
        metadata: vp_metadata, // TODO: validate VP metadata
        proof: _,
        proof_graph_name: _,
        filters: _filters_graph,
        disclosed_vcs: c14n_disclosed_vc_graphs,
    } = (&canonicalized_vp).try_into()?;

    // get PPID
    let ppid = get_ppid(&vp_metadata)?;
    println!("PPID: {:#?}", ppid);

    // get secret commitment
    let secret_commitment = get_secret_commitment(&vp_metadata)?;
    println!("secret_commitment: {:#?}", secret_commitment);

    // get predicates
    let predicates = get_predicates(&vp_metadata, &snark_verifying_keys)?;
    println!("predicates: {:#?}", predicates);

    // get issuer public keys
    let public_keys = c14n_disclosed_vc_graphs
        .iter()
        .map(|(_, vc)| get_public_keys_from_graphview(&vc.proof, key_graph))
        .collect::<Result<Vec<_>, _>>()?;
    println!("public_keys:\n{:#?}\n", public_keys);

    // if the VC is bound to secret or not
    let is_bounds = c14n_disclosed_vc_graphs
        .iter()
        .map(|(_, vc)| vc.is_bound())
        .collect::<Result<Vec<_>, _>>()?;

    // convert to Vecs
    let disclosed_vec = c14n_disclosed_vc_graphs
        .into_iter()
        .map(|(_, v)| v.into())
        .collect::<Vec<VerifiableCredentialTriples>>();

    // deserialize proof value into proof and index_map
    let (_, proof_value_bytes) = multibase::decode(proof_value_encoded)?;
    let ProofWithIndexMap { proof, index_map } = serde_cbor::from_slice(&proof_value_bytes)?;
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
        .zip(&is_bounds)
        .enumerate()
        .map(|(i, (disclosed_vc_triples, is_bound))| {
            get_disclosed_terms(disclosed_vc_triples, i, is_bound)
        })
        .collect::<Result<Vec<_>, RDFProofsError>>()?;
    println!("disclosed_terms:\n{:#?}\n", disclosed_terms);

    let term_counts = disclosed_terms
        .iter()
        .map(|t| {
            t.term_count
                .try_into()
                .map_err(|_| RDFProofsError::MessageSizeOverflow)
        })
        .collect::<Result<Vec<u32>, _>>()?;
    let params_for_commitment = generate_params(1);
    let params_and_pks = term_counts
        .iter()
        .zip(public_keys)
        .map(|(t, pk)| (generate_params(*t), pk));

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

    // build statements
    let mut statements = Statements::new();
    // statements for BBS+ signatures
    for (DisclosedTerms { disclosed, .. }, (params, public_key)) in
        disclosed_terms.iter().zip(params_and_pks)
    {
        statements.add(PoKBBSPlusStmt::new_statement_from_params(
            params,
            public_key,
            disclosed.clone(),
        ));
    }
    // statement for PPID
    let mut ppid_index = None;
    if let Some(ppid) = ppid {
        if let Some(domain) = domain {
            let base = generate_ppid_base(domain)?;
            statements.add(PedersenCommitmentStmt::new_statement_from_params(
                vec![base],
                ppid,
            ));
            ppid_index = Some(statements.len() - 1);
        }
    }
    // statement for secret commitment
    let mut secret_commitment_index = None;
    if let Some(s) = secret_commitment {
        statements.add(PedersenCommitmentStmt::new_statement_from_params(
            vec![params_for_commitment.h_0, params_for_commitment.h[0]],
            s,
        ));
        secret_commitment_index = Some(statements.len() - 1);
    }
    // statements for predicates
    let mut predicate_indexes = vec![];
    for predicate in &predicates {
        let mut public_inputs = vec![Fr::one()]; // predicate must return 1
        let mut public_vals = predicate
            .public
            .iter()
            .map(|(_, val)| hash_term_to_field(val.into(), &hasher))
            .collect::<Result<Vec<_>, _>>()?;
        public_inputs.append(&mut public_vals);

        statements.add(R1CSCircomVerifier::new_statement_from_params(
            public_inputs,
            predicate.snark_verifying_key.clone(),
        )?);
        predicate_indexes.push(statements.len() - 1);
    }
    println!("statements: {:?}", statements);

    // build meta statements
    let mut meta_statements = MetaStatements::new();

    // proof of equality for embedded secrets
    let mut secret_equiv_set: BTreeSet<(usize, usize)> = is_bounds
        .iter()
        .enumerate()
        .filter(|(_, &is_bound)| is_bound)
        .map(|(i, _)| (i, 0)) // `0` is the index for embedded secret in VC
        .collect();
    // add PPID to the proof of equalities if exists
    if let Some(idx) = ppid_index {
        // `0` corresponds to the committed secret in PPID
        secret_equiv_set.insert((idx, 0));
    }
    // add secret commitment to the proof of equalities if exists
    if let Some(idx) = secret_commitment_index {
        // `1` corresponds to the committed secret in Pedersen Commitment (`0` corresponds to the blinding)
        secret_equiv_set.insert((idx, 1));
    }
    if secret_equiv_set.len() > 1 {
        meta_statements.add_witness_equality(EqualWitnesses(secret_equiv_set));
    }

    // proof of equality
    for (equiv_c14n_id, equiv_vec) in equivs {
        // add equality for attributes in credentials
        let mut equiv_set: BTreeSet<(usize, usize)> = equiv_vec.into_iter().collect();

        // add equality for predicate private variables
        for (predicate, predicate_index) in predicates.iter().zip(&predicate_indexes) {
            if let NamedOrBlankNode::BlankNode(bnode_in_equiv) = &equiv_c14n_id.0 {
                if let Some(idx_in_predicate) = predicate
                    .private
                    .iter()
                    .position(|(_, bnode_in_private)| bnode_in_private == bnode_in_equiv)
                {
                    equiv_set.insert((*predicate_index, idx_in_predicate));
                }
            }
        }
        println!("equiv_set: {:?}", equiv_set);
        if equiv_set.len() > 1 {
            meta_statements.add_witness_equality(EqualWitnesses(equiv_set));
        }
    }

    // build proof spec
    let context = generate_proof_spec_context(&canonicalized_vp, &index_map)?;
    let proof_spec = ProofSpec::new(statements, meta_statements, vec![], Some(context));
    proof_spec.validate()?;

    // verify proof
    Ok(proof.verify::<R, BBSPlusHash>(
        rng,
        proof_spec,
        challenge.map(|v| v.as_bytes().to_vec()),
        Default::default(),
    )?)
}

pub fn verify_proof_string<R: RngCore>(
    rng: &mut R,
    vp: &str,
    key_graph: &str,
    challenge: Option<&str>,
    domain: Option<&str>,
    snark_verifying_keys: Option<HashMap<String, String>>,
) -> Result<(), RDFProofsError> {
    // construct input for `verify_proof` from string-based input
    let vp = get_dataset_from_nquads(vp)?;
    let key_graph = get_graph_from_ntriples(key_graph)?.into();
    let snark_verifying_key = match snark_verifying_keys {
        Some(predicate_id_and_vks) => {
            let m = predicate_id_and_vks
                .iter()
                .map(|(predicate_id, vk)| {
                    let Term::NamedNode(predicate_id) = get_term_from_string(predicate_id)? else {
                        return Err(RDFProofsError::InvalidPredicate)
                    };
                    Ok((predicate_id, multibase_to_ark(vk)?))
                })
                .collect::<Result<HashMap<_, VerifyingKey>, _>>()?;
            Some(m)
        }
        None => None,
    };

    verify_proof(rng, &vp, &key_graph, challenge, domain, snark_verifying_key)
}

fn get_ppid(metadata: &GraphView) -> Result<Option<G1Affine>, RDFProofsError> {
    let vp_subject = metadata
        .subject_for_predicate_object(TYPE, VERIFIABLE_PRESENTATION_TYPE)
        .ok_or(RDFProofsError::InvalidVP)?;
    let holder_subject = match metadata.object_for_subject_predicate(vp_subject, HOLDER) {
        Some(TermRef::NamedNode(n)) => n.as_str(),
        _ => return Ok(None),
    };
    let ppid_multibase = holder_subject
        .strip_prefix(PPID_PREFIX)
        .ok_or(RDFProofsError::InvalidPPID)?;
    Ok(Some(multibase_to_ark(ppid_multibase)?))
}

fn get_secret_commitment(metadata: &GraphView) -> Result<Option<G1Affine>, RDFProofsError> {
    let vp_subject = metadata
        .subject_for_predicate_object(TYPE, VERIFIABLE_PRESENTATION_TYPE)
        .ok_or(RDFProofsError::InvalidVP)?;
    let holder_subject = match metadata.object_for_subject_predicate(vp_subject, HOLDER) {
        Some(TermRef::NamedNode(n)) => NamedOrBlankNodeRef::NamedNode(n),
        Some(TermRef::BlankNode(n)) => NamedOrBlankNodeRef::BlankNode(n),
        _ => return Ok(None),
    };
    let commitment = if let Some(TermRef::Literal(commitment_multibase)) =
        metadata.object_for_subject_predicate(holder_subject, SECRET_COMMITMENT)
    {
        Some(multibase_to_ark(commitment_multibase.value())?)
    } else {
        None
    };
    Ok(commitment)
}

fn read_var_list(
    node: BlankNodeRef,
    result: &mut Vec<(String, Term)>,
    metadata: &GraphView,
) -> Result<(), RDFProofsError> {
    let Some(TermRef::BlankNode(var_and_val)) = metadata.object_for_subject_predicate(node, FIRST) else {
        return Err(RDFProofsError::InvalidPredicate)
    };
    let Some(TermRef::Literal(var)) = metadata.object_for_subject_predicate(var_and_val, PREDICATE_VAR) else {
        return Err(RDFProofsError::InvalidPredicate)
    };
    let Some(val) = metadata.object_for_subject_predicate(var_and_val, PREDICATE_VAL) else {
        return Err(RDFProofsError::InvalidPredicate)
    };
    result.push((var.value().to_string(), val.into()));

    match metadata.object_for_subject_predicate(node, REST) {
        Some(TermRef::BlankNode(rest)) => read_var_list(rest, result, metadata),
        Some(TermRef::NamedNode(rest)) if rest == NIL => Ok(()),
        _ => Err(RDFProofsError::InvalidPredicate),
    }
}

fn get_predicates(
    metadata: &GraphView,
    snark_verifying_keys: &Option<HashMap<NamedNode, VerifyingKey>>,
) -> Result<Vec<VerifierPredicateProofStatement>, RDFProofsError> {
    let mut result = vec![];

    let Some(snark_verifying_keys) = snark_verifying_keys else { return Ok(result) };

    let vp_subject = metadata
        .subject_for_predicate_object(TYPE, VERIFIABLE_PRESENTATION_TYPE)
        .ok_or(RDFProofsError::InvalidVP)?;

    for predicate in metadata.objects_for_subject_predicate(vp_subject, PREDICATE) {
        let predicate_subject = match predicate {
            TermRef::NamedNode(n) => Ok(NamedOrBlankNodeRef::NamedNode(n)),
            TermRef::BlankNode(n) => Ok(NamedOrBlankNodeRef::BlankNode(n)),
            TermRef::Literal(_) => Err(RDFProofsError::InvalidPredicate),
        }?;

        let TermRef::NamedNode(predicate_circuit) = metadata
            .object_for_subject_predicate(predicate_subject, CIRCUIT)
            .ok_or(RDFProofsError::MissingPredicateCircuit)? else {
                return Err(RDFProofsError::MissingPredicateCircuit)
            };

        let snark_verifying_key = snark_verifying_keys
            .get(&predicate_circuit.into_owned())
            .ok_or(RDFProofsError::MissingSnarkVK(
                predicate_circuit.to_string(),
            ))?;

        let mut privates = vec![];
        let Some(TermRef::BlankNode(private)) = metadata.object_for_subject_predicate(predicate_subject, PRIVATE) else {
            return Err(RDFProofsError::InvalidPredicate)
        };
        read_var_list(private, &mut privates, metadata)?;
        let privates = privates
            .iter()
            .map(|(s, t)| {
                if let Term::BlankNode(b) = t {
                    Ok((s.clone(), b.clone()))
                } else {
                    Err(RDFProofsError::InvalidPredicate)
                }
            })
            .collect::<Result<Vec<_>, RDFProofsError>>()?;

        let mut publics = vec![];
        let Some(TermRef::BlankNode(public)) = metadata.object_for_subject_predicate(predicate_subject, PUBLIC) else {
            return Err(RDFProofsError::InvalidPredicate)
        };
        read_var_list(public, &mut publics, metadata)?;

        result.push(VerifierPredicateProofStatement {
            snark_verifying_key: snark_verifying_key.clone(),
            private: privates,
            public: publics,
        });
    }

    Ok(result)
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
    is_bound: &bool,
) -> Result<DisclosedTerms, RDFProofsError> {
    let mut disclosed_terms = BTreeMap::<usize, Fr>::new();
    let mut equivs = HashMap::<NamedOrBlankNode, Vec<(usize, usize)>>::new();

    let DisclosedVerifiableCredential {
        document: disclosed_document,
        proof: disclosed_proof,
    } = disclosed_vc_triples;

    let mut current_term_index = 0;

    if !is_bound {
        disclosed_terms.insert(current_term_index, Fr::from(1));
    };
    current_term_index += 1;

    for (_, disclosed_triple) in disclosed_document {
        build_disclosed_terms(
            disclosed_triple,
            current_term_index,
            vc_index,
            &mut disclosed_terms,
            &mut equivs,
        )?;
        current_term_index += 3;
    }

    let delimiter = get_delimiter()?;
    disclosed_terms.insert(current_term_index, delimiter);
    current_term_index += 1;

    for (_, disclosed_triple) in disclosed_proof {
        build_disclosed_terms(
            disclosed_triple,
            current_term_index,
            vc_index,
            &mut disclosed_terms,
            &mut equivs,
        )?;
        current_term_index += 3;
    }
    Ok(DisclosedTerms {
        disclosed: disclosed_terms,
        equivs,
        term_count: current_term_index,
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

// TODO: to be integrated with `get_public_keys`
fn get_public_keys_from_graphview(
    proof_graph: &GraphView,
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
