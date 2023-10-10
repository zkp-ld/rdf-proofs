use crate::{
    common::{ProvingKey, R1CS},
    error::RDFProofsError,
    multibase_to_ark,
};
use serde::{Deserialize, Serialize};

pub struct Circuit {
    r1cs: R1CS,
    wasm: Vec<u8>,
    proving_key: ProvingKey,
}

impl Circuit {
    pub fn new(r1cs: &str, wasm: &str, proving_key: &str) -> Result<Self, RDFProofsError> {
        let r1cs: R1CS = multibase_to_ark(r1cs)?;
        let (_, wasm) = multibase::decode(wasm)?;
        let proving_key: ProvingKey = multibase_to_ark(proving_key)?;
        Ok(Self {
            r1cs,
            wasm,
            proving_key,
        })
    }

    pub fn get_r1cs(&self) -> R1CS {
        self.r1cs.clone()
    }

    pub fn get_wasm(&self) -> Vec<u8> {
        self.wasm.clone()
    }

    pub fn get_proving_key(&self) -> ProvingKey {
        self.proving_key.clone()
    }
}

#[derive(Serialize, Deserialize)]
pub struct CircuitString {
    #[serde(rename = "r1cs")]
    pub circuit_r1cs: String,
    #[serde(rename = "wasm")]
    pub circuit_wasm: String,
    #[serde(rename = "provingKey")]
    pub snark_proving_key: String,
}
