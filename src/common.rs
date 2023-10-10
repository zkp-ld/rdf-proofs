use crate::{
    constants::{DELIMITER, MAP_TO_SCALAR_AS_HASH_DST, NYM_IRI_PREFIX},
    context::{
        CREATED, CRYPTOSUITE, DATA_INTEGRITY_PROOF, PREDICATE_VAL, PREDICATE_VAR, SCO_DATE,
        SCO_DATETIME, VERIFICATION_METHOD,
    },
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
use chrono::{DateTime, NaiveDate, Utc};
use legogroth16::circom::{CircomCircuit as CircomCircuitOrig, R1CS as R1CSOrig};
use multibase::Base;
use oxrdf::{
    dataset::GraphView,
    vocab::{
        self,
        rdf::{FIRST, NIL, REST, TYPE},
        xsd::{self, DATE, DATE_TIME, INTEGER},
    },
    BlankNode, BlankNodeRef, Dataset, Graph, Literal, LiteralRef, NamedNode, NamedNodeRef,
    NamedOrBlankNode, SubjectRef, Term, TermRef, Triple, TripleRef,
};
use oxsdatatypes::DateTime as DateTimeOxsDataTypes;
use oxttl::{NQuadsParser, NTriplesParser};
use proof_system::{
    prelude::R1CSCircomWitness as R1CSCircomWitnessOrig,
    proof::Proof as ProofOrig,
    statement::{
        bbs_plus::PoKBBSSignatureG1 as PoKBBSSignatureG1Stmt,
        ped_comm::PedersenCommitment,
        r1cs_legogroth16::{ProvingKey as ProvingKeyOrig, VerifyingKey as VerifyingKeyOrig},
        Statements as StatementsOrig,
    },
    witness::PoKBBSSignatureG1 as PoKBBSSignatureG1Wit,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
};

pub type Fr = <Bls12_381 as Pairing>::ScalarField;
pub type Proof = ProofOrig<Bls12_381, G1Affine>;
pub type Statements = StatementsOrig<Bls12_381, <Bls12_381 as Pairing>::G1Affine>;
pub type BBSPlusHash = Blake2b512;
pub type BBSPlusDefaultFieldHasher = DefaultFieldHasher<BBSPlusHash>;
pub type BBSPlusParams = SignatureParamsG1<Bls12_381>;
pub type BBSPlusKeypair = KeypairG2<Bls12_381>;
pub type BBSPlusSecretKey = SecretKey<Fr>;
pub type BBSPlusPublicKey = PublicKeyG2<Bls12_381>;
pub type BBSPlusSignature = SignatureG1<Bls12_381>;
pub type PoKBBSPlusStmt<E> = PoKBBSSignatureG1Stmt<E>;
pub type PoKBBSPlusWit<E> = PoKBBSSignatureG1Wit<E>;
pub type PedersenCommitmentStmt = PedersenCommitment<G1Affine>;
pub type ProvingKey = ProvingKeyOrig<Bls12_381>;
pub type VerifyingKey = VerifyingKeyOrig<Bls12_381>;
pub type CircomCircuit = CircomCircuitOrig<Bls12_381>;
pub type R1CS = R1CSOrig<Bls12_381>;
pub type R1CSCircomWitness = R1CSCircomWitnessOrig<Bls12_381>;

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

pub fn ark_to_multibase<A: CanonicalSerialize>(
    base: Base,
    ark: &A,
) -> Result<String, RDFProofsError> {
    let mut bytes = Vec::new();
    ark.serialize_compressed(&mut bytes)?;
    Ok(multibase::encode(base, bytes))
}

pub fn ark_to_base64url<A: CanonicalSerialize>(ark: &A) -> Result<String, RDFProofsError> {
    ark_to_multibase(Base::Base64Url, ark)
}

pub fn multibase_to_ark<A: CanonicalDeserialize>(s: &str) -> Result<A, RDFProofsError> {
    let (_, bytes) = multibase::decode(s)?;
    let ark = A::deserialize_compressed(&*bytes)?;
    Ok(ark)
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

pub fn get_hasher() -> BBSPlusDefaultFieldHasher {
    <BBSPlusDefaultFieldHasher as HashToField<Fr>>::new(MAP_TO_SCALAR_AS_HASH_DST)
}

pub fn hash_terms_to_field(
    terms: &Vec<Term>,
    hasher: &BBSPlusDefaultFieldHasher,
) -> Result<Vec<Fr>, RDFProofsError> {
    terms
        .iter()
        .map(|term| hash_term_to_field(term.as_ref(), hasher))
        .collect()
}

pub fn hash_term_to_field(
    term: TermRef,
    hasher: &BBSPlusDefaultFieldHasher,
) -> Result<Fr, RDFProofsError> {
    // limit integers to 64-bits
    match term {
        TermRef::Literal(v) if v.datatype() == INTEGER => {
            let num: i64 = v.value().parse()?;
            Ok(Fr::from(num))
        }
        TermRef::Literal(v) if v.datatype() == DATE_TIME || v.datatype() == SCO_DATETIME => {
            let datetime: DateTime<Utc> = v.value().parse()?;
            let timestamp = datetime.timestamp();
            Fr::try_from(timestamp)
                .map_err(|_| RDFProofsError::InvalidDateTime(v.value().to_string()))
        }
        TermRef::Literal(v) if v.datatype() == DATE || v.datatype() == SCO_DATE => {
            let date: NaiveDate = v.value().parse()?;
            let datetime = date
                .and_hms_opt(0, 0, 0)
                .ok_or(RDFProofsError::InvalidDateTime(v.value().to_string()))?;
            let timestamp = datetime.timestamp();
            Fr::try_from(timestamp)
                .map_err(|_| RDFProofsError::InvalidDateTime(v.value().to_string()))
        }
        _ => hasher
            .hash_to_field(term.to_string().as_bytes(), 1)
            .pop()
            .ok_or(RDFProofsError::HashToField),
    }
}

pub fn hash_byte_to_field(
    byte: &[u8],
    hasher: &BBSPlusDefaultFieldHasher,
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

pub(crate) fn configure_proof_core(
    proof_options: &Graph,
    cryptosuite: &str,
) -> Result<Graph, RDFProofsError> {
    let mut proof_config = proof_options.clone();

    // if `proof_options.type` is not set to `DataIntegrityProof`
    // then `INVALID_PROOF_CONFIGURATION_ERROR` must be raised
    let proof_options_subject = proof_options
        .subject_for_predicate_object(TYPE, DATA_INTEGRITY_PROOF)
        .ok_or(RDFProofsError::InvalidProofConfiguration)?;

    // if `proof_options.cryptosuite` is given and its value is not `cryptosuite`
    // then `INVALID_PROOF_CONFIGURATION_ERROR` must be raised
    let given_cryptosuite =
        proof_options.object_for_subject_predicate(proof_options_subject, CRYPTOSUITE);
    if let Some(TermRef::Literal(v)) = given_cryptosuite {
        if v.value() != cryptosuite {
            return Err(RDFProofsError::InvalidProofConfiguration);
        }
    } else {
        proof_config.insert(TripleRef::new(
            proof_options_subject,
            CRYPTOSUITE,
            LiteralRef::new_simple_literal(cryptosuite),
        ));
    }

    // if `proof_options.created` is not a valid xsd:dateTime,
    // `INVALID_PROOF_DATETIME_ERROR` must be raised
    let created = proof_options.object_for_subject_predicate(proof_options_subject, CREATED);
    if let Some(TermRef::Literal(v)) = created {
        let (datetime, typ, _) = v.destruct();
        if DateTimeOxsDataTypes::from_str(datetime).is_err()
            || !typ.is_some_and(|t| t == vocab::xsd::DATE_TIME)
        {
            return Err(RDFProofsError::InvalidProofDatetime);
        }
    } else {
        // generate current datetime if not given
        proof_config.insert(TripleRef::new(
            proof_options_subject,
            CREATED,
            LiteralRef::new_typed_literal(&format!("{:?}", Utc::now()), xsd::DATE_TIME),
        ));
    }

    Ok(proof_config)
}

pub(crate) fn canonicalize_graph_into_terms(graph: &Graph) -> Result<Vec<Term>, RDFProofsError> {
    let (canonicalized_graph, _) = canonicalize_graph(graph)?;
    let canonicalized_triples = rdf_canon::sort_graph(&canonicalized_graph);
    Ok(canonicalized_triples
        .into_iter()
        .flat_map(|t| vec![t.subject.into(), t.predicate.into(), t.object])
        .collect())
}

pub(crate) fn get_term_from_string(term_string: &str) -> Result<Term, RDFProofsError> {
    let re_iri = Regex::new(r"^<([^>]+)>$")?;
    let re_blank_node = Regex::new(r"^_:(.+)$")?;
    let re_simple_literal = Regex::new(r#"^"([^"]+)"$"#)?;
    let re_typed_literal = Regex::new(r#"^"([^"]+)"\^\^<([^>]+)>$"#)?;
    let re_literal_with_langtag = Regex::new(r#"^"([^"]+)"@(.+)$"#)?;

    if let Some(caps) = re_iri.captures(term_string) {
        Ok(NamedNode::new_unchecked(&caps[1]).into())
    } else if let Some(caps) = re_blank_node.captures(term_string) {
        Ok(BlankNode::new_unchecked(&caps[1]).into())
    } else if let Some(caps) = re_simple_literal.captures(term_string) {
        Ok(Literal::new_simple_literal(&caps[1]).into())
    } else if let Some(caps) = re_typed_literal.captures(term_string) {
        Ok(Literal::new_typed_literal(&caps[1], NamedNode::new_unchecked(&caps[2])).into())
    } else if let Some(caps) = re_literal_with_langtag.captures(term_string) {
        Ok(Literal::new_language_tagged_literal(&caps[1], &caps[2])?.into())
    } else {
        Err(RDFProofsError::TtlTermParse(term_string.to_string()))
    }
}

pub(crate) fn read_private_var_list(
    node: BlankNodeRef,
    result: &mut Vec<(String, NamedOrBlankNode)>,
    graph: &GraphView,
) -> Result<(), RDFProofsError> {
    let Some(TermRef::BlankNode(var_and_val)) = graph.object_for_subject_predicate(node, FIRST) else {
        return Err(RDFProofsError::InvalidPredicate)
    };
    let Some(TermRef::Literal(var)) = graph.object_for_subject_predicate(var_and_val, PREDICATE_VAR) else {
        return Err(RDFProofsError::InvalidPredicate)
    };
    let val: NamedOrBlankNode =
        if let Some(val) = graph.object_for_subject_predicate(var_and_val, PREDICATE_VAL) {
            match val {
                TermRef::NamedNode(n) => Ok(n.into()),
                TermRef::BlankNode(n) => Ok(n.into()),
                TermRef::Literal(_) => Err(RDFProofsError::InvalidPredicate),
            }
        } else {
            return Err(RDFProofsError::InvalidPredicate);
        }?;
    result.push((var.value().to_string(), val.into()));

    match graph.object_for_subject_predicate(node, REST) {
        Some(TermRef::BlankNode(rest)) => read_private_var_list(rest, result, graph),
        Some(TermRef::NamedNode(rest)) if rest == NIL => Ok(()),
        _ => Err(RDFProofsError::InvalidPredicate),
    }
}

pub(crate) fn read_public_var_list(
    node: BlankNodeRef,
    result: &mut Vec<(String, Term)>,
    graph: &GraphView,
) -> Result<(), RDFProofsError> {
    let Some(TermRef::BlankNode(var_and_val)) = graph.object_for_subject_predicate(node, FIRST) else {
        return Err(RDFProofsError::InvalidPredicate)
    };
    let Some(TermRef::Literal(var)) = graph.object_for_subject_predicate(var_and_val, PREDICATE_VAR) else {
        return Err(RDFProofsError::InvalidPredicate)
    };
    let Some(val) = graph.object_for_subject_predicate(var_and_val, PREDICATE_VAL) else {
        return Err(RDFProofsError::InvalidPredicate)
    };
    result.push((var.value().to_string(), val.into()));

    match graph.object_for_subject_predicate(node, REST) {
        Some(TermRef::BlankNode(rest)) => read_public_var_list(rest, result, graph),
        Some(TermRef::NamedNode(rest)) if rest == NIL => Ok(()),
        _ => Err(RDFProofsError::InvalidPredicate),
    }
}

#[cfg(test)]
mod tests {
    use super::{get_hasher, hash_term_to_field, Fr};
    use ark_ff::BigInt;
    use oxrdf::{
        vocab::xsd::{DATE, DATE_TIME, INTEGER},
        LiteralRef, NamedNodeRef, TermRef,
    };

    #[test]
    fn hash_terms_success() {
        let hasher = get_hasher();

        let eqs: Vec<(TermRef, Fr)> = vec![
            (
                NamedNodeRef::new_unchecked("did:example:john").into(),
                BigInt([
                    2024815526171708096,
                    2099760857422642053,
                    7708857115834156063,
                    3809904842201934428,
                ])
                .into(),
            ),
            (
                LiteralRef::new_typed_literal("123", INTEGER).into(),
                BigInt([123, 0, 0, 0]).into(),
            ),
            (
                LiteralRef::new_typed_literal("-123", INTEGER).into(),
                BigInt([
                    18446744069414584198,
                    6034159408538082302,
                    3691218898639771653,
                    8353516859464449352,
                ])
                .into(),
            ),
            (
                LiteralRef::new_typed_literal("9223372036854775807", INTEGER).into(),
                BigInt([9223372036854775807, 0, 0, 0]).into(),
            ),
            (
                LiteralRef::new_typed_literal("1970-01-01", DATE).into(),
                BigInt([0, 0, 0, 0]).into(),
            ),
            (
                LiteralRef::new_typed_literal("1970-01-01T00:00:00Z", DATE_TIME).into(),
                BigInt([0, 0, 0, 0]).into(),
            ),
            (
                LiteralRef::new_typed_literal("2022-01-01", DATE).into(),
                BigInt([1640995200, 0, 0, 0]).into(),
            ),
            (
                LiteralRef::new_typed_literal("2022-01-01T00:00:00Z", DATE_TIME).into(),
                BigInt([1640995200, 0, 0, 0]).into(),
            ),
            // Times less than one second are rounded down
            (
                LiteralRef::new_typed_literal("2022-01-01T00:00:00.12345678Z", DATE_TIME).into(),
                BigInt([1640995200, 0, 0, 0]).into(),
            ),
            (
                LiteralRef::new_typed_literal("0000-01-01", DATE).into(),
                BigInt([
                    18446744007247365121,
                    6034159408538082302,
                    3691218898639771653,
                    8353516859464449352,
                ])
                .into(),
            ),
            (
                LiteralRef::new_typed_literal("0000-01-01T00:00:00Z", DATE_TIME).into(),
                BigInt([
                    18446744007247365121,
                    6034159408538082302,
                    3691218898639771653,
                    8353516859464449352,
                ])
                .into(),
            ),
        ];

        for (term, hashed) in eqs {
            assert_eq!(hash_term_to_field(term, &hasher).unwrap(), hashed);
        }
    }

    #[test]
    fn hash_terms_failed() {
        let hasher = get_hasher();

        assert!(matches!(
            hash_term_to_field(
                LiteralRef::new_typed_literal("123.456", INTEGER).into(),
                &hasher
            ),
            Err(crate::error::RDFProofsError::ParseInt(_))
        ));

        // 9223372036854775808 = i64.MAX + 1
        assert!(matches!(
            hash_term_to_field(
                LiteralRef::new_typed_literal("9223372036854775808", INTEGER).into(),
                &hasher
            ),
            Err(crate::error::RDFProofsError::ParseInt(_))
        ));

        assert!(matches!(
            hash_term_to_field(
                LiteralRef::new_typed_literal("1234-56-78T99:99:99Z", DATE_TIME).into(),
                &hasher
            ),
            Err(crate::error::RDFProofsError::DateTimeParse(_))
        ));
    }
}
