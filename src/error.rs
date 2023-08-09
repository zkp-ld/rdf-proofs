use ark_serialize::SerializationError;
use bbs_plus::prelude::BBSPlusError;
use multibase;
use oxiri::IriParseError;
use oxrdf::BlankNodeIdParseError;
use rdf_canon::CanonicalizationError;

#[derive(Debug)]
pub enum RDFProofsError {
    Canonicalization(CanonicalizationError),
    BBSPlus(BBSPlusError),
    HashToField,
    Serialization(SerializationError),
    ProofTransformation,
    InvalidProofConfiguration,
    InvalidProofDatetime,
    ProofGeneration,
    InvalidVerificationMethodURL,
    InvalidVerificationMethod,
    MalformedProof,
    Multibase(multibase::Error),
}

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
        Self::Serialization(e)
    }
}

impl From<multibase::Error> for RDFProofsError {
    fn from(e: multibase::Error) -> Self {
        Self::Multibase(e)
    }
}

// TODO: fix name
#[derive(Debug)]
pub enum DeriveProofError {
    CanonicalizationError(CanonicalizationError),
    InvalidVCPairs,
    IriParseError(IriParseError),
    VCWithoutProofValue,
    VCWithoutVCType,
    VCWithInvalidProofValue,
    InvalidVCGraphName,
    BlankNodeIdParseError(BlankNodeIdParseError),
    DeAnonymizationError,
    InvalidVP,
    BlankNodeCollisionError,
    DisclosedVCIsNotSubsetOfOriginalVC,
    DeriveProofValueError,
    InternalError(String),
}

// TODO: implement Error trait
// impl Error for DeriveProofError {}
// impl std::fmt::Display for DeriveProofError {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         todo!()
//     }
// }

impl From<IriParseError> for DeriveProofError {
    fn from(e: IriParseError) -> Self {
        Self::IriParseError(e)
    }
}

impl From<CanonicalizationError> for DeriveProofError {
    fn from(e: CanonicalizationError) -> Self {
        Self::CanonicalizationError(e)
    }
}

impl From<BlankNodeIdParseError> for DeriveProofError {
    fn from(e: BlankNodeIdParseError) -> Self {
        Self::BlankNodeIdParseError(e)
    }
}
