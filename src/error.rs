use ark_serialize::SerializationError;
use bbs_plus::prelude::BBSPlusError;
use multibase;
use oxiri::IriParseError;
use oxrdf::BlankNodeIdParseError;
use proof_system::prelude::ProofSystemError;
use rdf_canon::CanonicalizationError;
use std::error::Error;

#[derive(Debug)]
pub enum RDFProofsError {
    Canonicalization(CanonicalizationError),
    BBSPlus(BBSPlusError),
    HashToField,
    ArkSerialization(SerializationError),
    CBORSerialization(serde_cbor::Error),
    ProofTransformation,
    InvalidProofConfiguration,
    InvalidProofDatetime,
    ProofGeneration,
    InvalidVerificationMethodURL,
    InvalidVerificationMethod,
    MalformedProof,
    Multibase(multibase::Error),
    InvalidVCPairs,
    IriParse(IriParseError),
    VCWithoutProofValue,
    VCWithInvalidProofValue,
    VCWithoutVCType,
    InvalidVCGraphName,
    BlankNodeIdParse(BlankNodeIdParseError),
    DeAnonymization,
    InvalidVP,
    BlankNodeCollision,
    DisclosedVCIsNotSubsetOfOriginalVC,
    DeriveProofValue,
    ProofSystem(ProofSystemError),
    Other(String),
}

impl std::fmt::Display for RDFProofsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RDFProofsError::Canonicalization(_) => write!(f, "canonicalization error"),
            RDFProofsError::BBSPlus(_) => write!(f, "BBS+ error"),
            RDFProofsError::HashToField => write!(f, "hash to field is failed"),
            RDFProofsError::ArkSerialization(_) => write!(f, "arkworks serialization error"),
            RDFProofsError::CBORSerialization(_) => write!(f, "CBOR serialization error"),
            RDFProofsError::ProofTransformation => write!(f, "proof transformation error"),
            RDFProofsError::InvalidProofConfiguration => {
                write!(f, "invalid proof configuration error")
            }
            RDFProofsError::InvalidProofDatetime => write!(f, "invalid proof datetime error"),
            RDFProofsError::ProofGeneration => write!(f, "proof generation error"),
            RDFProofsError::InvalidVerificationMethodURL => {
                write!(f, "invalid verification method URL error")
            }
            RDFProofsError::InvalidVerificationMethod => {
                write!(f, "invalid verification method error")
            }
            RDFProofsError::MalformedProof => write!(f, "malformed proof error"),
            RDFProofsError::Multibase(_) => write!(f, "multibase error"),
            RDFProofsError::InvalidVCPairs => write!(f, "invalid VC pairs error"),
            RDFProofsError::IriParse(_) => write!(f, "IRI parse error"),
            RDFProofsError::VCWithoutProofValue => write!(f, "VC without proof value error"),
            RDFProofsError::VCWithInvalidProofValue => {
                write!(f, "VC with invalid proof value error")
            }
            RDFProofsError::VCWithoutVCType => write!(f, "VC without VC type error"),
            RDFProofsError::InvalidVCGraphName => write!(f, "invalid VC graph name error"),
            RDFProofsError::BlankNodeIdParse(_) => write!(f, "blank node ID parse error"),
            RDFProofsError::DeAnonymization => write!(f, "deanonymization error"),
            RDFProofsError::InvalidVP => write!(f, "invalid VP error"),
            RDFProofsError::BlankNodeCollision => write!(f, "blank node collision error"),
            RDFProofsError::DisclosedVCIsNotSubsetOfOriginalVC => {
                write!(f, "disclosed VC is not subset of original VC error")
            }
            RDFProofsError::DeriveProofValue => write!(f, "derive proof value error"),
            RDFProofsError::Other(msg) => write!(f, "other error: {}", msg),
            RDFProofsError::ProofSystem(_) => write!(f, "proof system error"),
        }
    }
}

impl Error for RDFProofsError {}

impl From<CanonicalizationError> for RDFProofsError {
    fn from(e: CanonicalizationError) -> Self {
        Self::Canonicalization(e)
    }
}

impl From<BBSPlusError> for RDFProofsError {
    fn from(e: BBSPlusError) -> Self {
        Self::BBSPlus(e)
    }
}

impl From<SerializationError> for RDFProofsError {
    fn from(e: SerializationError) -> Self {
        Self::ArkSerialization(e)
    }
}

impl From<serde_cbor::Error> for RDFProofsError {
    fn from(e: serde_cbor::Error) -> Self {
        Self::CBORSerialization(e)
    }
}

impl From<multibase::Error> for RDFProofsError {
    fn from(e: multibase::Error) -> Self {
        Self::Multibase(e)
    }
}

impl From<IriParseError> for RDFProofsError {
    fn from(e: IriParseError) -> Self {
        Self::IriParse(e)
    }
}

impl From<BlankNodeIdParseError> for RDFProofsError {
    fn from(e: BlankNodeIdParseError) -> Self {
        Self::BlankNodeIdParse(e)
    }
}

impl From<ProofSystemError> for RDFProofsError {
    fn from(e: ProofSystemError) -> Self {
        Self::ProofSystem(e)
    }
}
