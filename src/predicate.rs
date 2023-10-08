use crate::{
    common::{CircomCircuit, ProvingKey, R1CSFile, R1CS},
    error::RDFProofsError,
};
use ark_std::rand::RngCore;
use oxrdf::{BlankNode, NamedNode, NamedOrBlankNode, Term};
use std::{
    collections::HashMap,
    io::{BufReader, Cursor},
};

pub struct Circuit {
    pub circuit_id: NamedNode,
    r1cs: R1CS,
    wasm_bytes: Vec<u8>,
    circuit: CircomCircuit,
}

impl Circuit {
    pub fn new(
        circuit_id: NamedNode,
        r1cs: Vec<u8>,
        wasm_bytes: Vec<u8>,
    ) -> Result<Self, RDFProofsError> {
        let r1cs: R1CS = R1CSFile::new(BufReader::new(Cursor::new(r1cs)))?.into();
        let circuit = CircomCircuit::setup(r1cs.clone());
        Ok(Self {
            circuit_id,
            r1cs,
            wasm_bytes,
            circuit,
        })
    }

    pub fn generate_proving_key<R: RngCore>(
        &self,
        commit_witness_count: u32,
        rng: &mut R,
    ) -> Result<ProvingKey, RDFProofsError> {
        Ok(self
            .circuit
            .clone()
            .generate_proving_key(commit_witness_count, rng)?)
    }

    pub fn get_r1cs(&self) -> R1CS {
        self.r1cs.clone()
    }

    pub fn get_wasm_bytes(&self) -> Vec<u8> {
        self.wasm_bytes.clone()
    }
}

pub struct PredicateProofStatement {
    pub circuit: Circuit,
    pub snark_proving_key: ProvingKey,
    pub private: Vec<(String, BlankNode)>,
    pub public: Vec<(String, Term)>,
}

impl PredicateProofStatement {
    pub fn deanon_privates(
        &self,
        deanon_map: &HashMap<NamedOrBlankNode, Term>,
    ) -> Result<Vec<(String, Term)>, RDFProofsError> {
        let resolved_private = self
            .private
            .iter()
            .map(|(k, v)| {
                Ok((
                    k.clone(),
                    deanon_map
                        .get(&v.to_owned().into())
                        .ok_or(RDFProofsError::InvalidPredicate)?
                        .clone(),
                ))
            })
            .collect::<Result<Vec<_>, RDFProofsError>>()?;
        Ok(resolved_private)
    }

    pub fn canonicalize_privates(
        &self,
        issued_identifiers_map: &HashMap<String, String>,
    ) -> Result<Vec<(String, BlankNode)>, RDFProofsError> {
        let canonical_privates = self
            .private
            .iter()
            .map(|(k, v)| {
                let canonical_id = issued_identifiers_map
                    .get(v.as_str())
                    .ok_or(RDFProofsError::InvalidPredicate)?;
                Ok((k.clone(), BlankNode::new_unchecked(canonical_id)))
            })
            .collect::<Result<Vec<_>, RDFProofsError>>()?;
        Ok(canonical_privates)
    }
}

pub struct PredicateProofStatementString {
    pub circuit_id: String,
    pub circuit_r1cs: Vec<u8>,
    pub circuit_wasm: Vec<u8>,
    pub snark_proving_key: String,
    pub private: Vec<(String, String)>,
    pub public: Vec<(String, String)>,
}
