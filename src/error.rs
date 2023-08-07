use ark_serialize::SerializationError;
use bbs_plus::prelude::BBSPlusError;
use oxiri::IriParseError;
use oxrdf::BlankNodeIdParseError;
use rdf_canon::CanonicalizationError;

#[derive(Debug)]
pub enum SignError {
    CanonicalizationError(CanonicalizationError),
    BBSPlusError(BBSPlusError),
    HashToFieldError,
    SerializationError(SerializationError),
    InvalidProofOptionsError,
}

impl From<CanonicalizationError> for SignError {
    fn from(e: CanonicalizationError) -> Self {
        Self::CanonicalizationError(e)
    }
}

impl From<BBSPlusError> for SignError {
    fn from(e: BBSPlusError) -> Self {
        Self::BBSPlusError(e)
    }
}

impl From<SerializationError> for SignError {
    fn from(e: SerializationError) -> Self {
        Self::SerializationError(e)
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
