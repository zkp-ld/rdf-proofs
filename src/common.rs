use crate::{
    constants::{DELIMITER, MAP_TO_SCALAR_AS_HASH_DST, NYM_IRI_PREFIX},
    context::{DATA_INTEGRITY_PROOF, VERIFICATION_METHOD},
    error::RDFProofsError,
    vc::{DisclosedVerifiableCredential, VerifiableCredentialTriples},
    VerifiableCredential,
};
use ark_bls12_381::{Bls12_381, G1Affine};
use ark_ec::pairing::Pairing;
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bbs_plus::{
    setup::{KeypairG2, PublicKeyG2, SecretKey, SignatureParamsG1},
    signature::SignatureG1,
};
use blake2::Blake2b512;
use multibase::Base;
use oxrdf::{
    vocab::rdf::TYPE, BlankNode, Dataset, Graph, NamedNode, NamedNodeRef, SubjectRef, Term,
    TermRef, Triple,
};
use oxttl::{NQuadsParser, NTriplesParser};
use proof_system::{
    proof::Proof as ProofOrig, statement::bbs_plus::PoKBBSSignatureG1 as PoKBBSSignatureG1Stmt,
    statement::Statements as StatementsOrig, witness::PoKBBSSignatureG1 as PoKBBSSignatureG1Wit,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

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

pub fn serialize_ark<S: serde::Serializer, A: CanonicalSerialize>(
    ark: &A,
    ser: S,
) -> Result<S::Ok, S::Error> {
    let mut bytes = vec![];
    ark.serialize_compressed(&mut bytes)
        .map_err(serde::ser::Error::custom)?;
    ser.serialize_bytes(&bytes)
}

pub fn deserialize_ark<'de, D: serde::Deserializer<'de>, A: CanonicalDeserialize>(
    de: D,
) -> Result<A, D::Error> {
    let s: &[u8] = serde::Deserialize::deserialize(de)?;
    A::deserialize_compressed(s).map_err(serde::de::Error::custom)
}

#[derive(Serialize)]
struct ProofSpecContext(pub String, pub Vec<StatementIndexMap>);

pub(crate) fn generate_proof_spec_context(
    vp: &Dataset,
    statement_index_map: &Vec<StatementIndexMap>,
) -> Result<Vec<u8>, RDFProofsError> {
    let serialized_vp = rdf_canon::serialize(&vp);
    let serialized_vp_with_index_map = ProofSpecContext(serialized_vp, statement_index_map.clone());
    Ok(serde_cbor::to_vec(&serialized_vp_with_index_map)?) // TODO: CBOR is overkill as we do not need deserialization
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct StatementIndexMap {
    #[serde(rename = "a")]
    document_map: Vec<usize>,
    #[serde(rename = "b")]
    document_len: usize,
    #[serde(rename = "c")]
    proof_map: Vec<usize>,
    #[serde(rename = "d")]
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

#[derive(Serialize, Deserialize)]
pub struct ProofWithIndexMap {
    #[serde(
        rename = "a",
        serialize_with = "serialize_ark",
        deserialize_with = "deserialize_ark"
    )]
    pub proof: Proof,
    #[serde(rename = "b")]
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

pub fn hash_byte_to_field(
    byte: &[u8],
    hasher: &DefaultFieldHasher<Blake2b512>,
) -> Result<Fr, RDFProofsError> {
    hasher
        .hash_to_field(byte, 1)
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
