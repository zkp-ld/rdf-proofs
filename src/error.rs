use oxrdf::NamedNode;

#[derive(Debug)]
pub enum RDFProofsError {
    Canonicalization(rdf_canon::CanonicalizationError),
    BBSPlus(bbs_plus::prelude::BBSPlusError),
    HashToField,
    ArkSerialization(ark_serialize::SerializationError),
    CBORSerialization(serde_cbor::Error),
    ProofTransformation,
    InvalidProofConfiguration,
    InvalidProofDatetime,
    ProofGeneration,
    InvalidVerificationMethodURL,
    InvalidVerificationMethod,
    MalformedProof,
    Multibase(multibase::Error),
    MissingInputToDeriveProof,
    IriParse(oxiri::IriParseError),
    TtlParse(oxttl::ParseError),
    InvalidDeanonMapFormat(String),
    VCWithoutProofValue,
    VCWithInvalidProofValue,
    VCWithoutVCType,
    VCWithoutCryptosuite,
    VCWithUnsupportedCryptosuite,
    InvalidVCGraphName,
    BlankNodeIdParse(oxrdf::BlankNodeIdParseError),
    LanguageTagParse(oxrdf::LanguageTagParseError),
    DeAnonymization,
    InvalidVP,
    BlankNodeCollision,
    DisclosedVCIsNotSubsetOfOriginalVC,
    DeriveProofValue,
    ProofSystem(proof_system::prelude::ProofSystemError),
    RDFStarUnsupported,
    MissingChallengeInVP,
    MissingChallengeInRequest,
    MismatchedChallenge,
    MissingDomainInVP,
    MissingDomainInRequest,
    MismatchedDomain,
    MissingProofConfigLiteral(NamedNode),
    InvalidChallengeDatatype,
    MessageSizeOverflow,
    MissingSecret,
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
            RDFProofsError::MissingInputToDeriveProof => {
                write!(
                    f,
                    "either VCs or a committed secret must be provided as input to `derive_proof`"
                )
            }
            RDFProofsError::IriParse(_) => write!(f, "IRI parse error"),
            RDFProofsError::TtlParse(e) => write!(f, "N-Triples / N-Quads parse error: {}", e),
            RDFProofsError::InvalidDeanonMapFormat(e) => {
                write!(f, "invalid deanon map error: {}", e)
            }
            RDFProofsError::VCWithoutProofValue => write!(f, "VC without proof value error"),
            RDFProofsError::VCWithInvalidProofValue => {
                write!(f, "VC with invalid proof value error")
            }
            RDFProofsError::VCWithoutVCType => write!(f, "VC without VC type error"),
            RDFProofsError::VCWithoutCryptosuite => write!(f, "VC without cryptosuite error"),
            RDFProofsError::VCWithUnsupportedCryptosuite => {
                write!(f, "VC without cryptosuite error")
            }
            RDFProofsError::InvalidVCGraphName => write!(f, "invalid VC graph name error"),
            RDFProofsError::BlankNodeIdParse(_) => write!(f, "blank node ID parse error"),
            RDFProofsError::LanguageTagParse(_) => write!(f, "language tag parse error"),
            RDFProofsError::DeAnonymization => write!(f, "deanonymization error"),
            RDFProofsError::InvalidVP => write!(f, "invalid VP error"),
            RDFProofsError::BlankNodeCollision => write!(f, "blank node collision error"),
            RDFProofsError::DisclosedVCIsNotSubsetOfOriginalVC => {
                write!(f, "disclosed VC is not subset of original VC error")
            }
            RDFProofsError::DeriveProofValue => write!(f, "derive proof value error"),
            RDFProofsError::ProofSystem(_) => write!(f, "proof system error"),
            RDFProofsError::RDFStarUnsupported => write!(f, "RDF-star is not supported"),
            RDFProofsError::MissingChallengeInVP => {
                write!(f, "verifier's required challenge is not present in VP")
            }
            RDFProofsError::MissingChallengeInRequest => write!(
                f,
                "challenge is in VP but not present in verifier's request"
            ),
            RDFProofsError::MismatchedChallenge => {
                write!(f, "challenge does not match the expected value")
            }
            RDFProofsError::MissingDomainInVP => {
                write!(f, "verifier's required domain is not present in VP")
            }
            RDFProofsError::MissingDomainInRequest => {
                write!(f, "domain is in VP but not present in verifier's request")
            }
            RDFProofsError::MismatchedDomain => {
                write!(f, "domain does not match the expected value")
            }
            RDFProofsError::MissingProofConfigLiteral(n) => {
                write!(f, "`{}` is not in proof config", n)
            }
            RDFProofsError::InvalidChallengeDatatype => {
                write!(f, "challenge in VP has invalid datatype")
            }
            RDFProofsError::MessageSizeOverflow => {
                write!(f, "message size exceed 32-bit integer limit")
            }
            RDFProofsError::MissingSecret => {
                write!(
                    f,
                    "secret must be given to derive proof with blind signature"
                )
            }
            RDFProofsError::Other(msg) => write!(f, "other error: {}", msg),
        }
    }
}

impl std::error::Error for RDFProofsError {}

impl From<rdf_canon::CanonicalizationError> for RDFProofsError {
    fn from(e: rdf_canon::CanonicalizationError) -> Self {
        Self::Canonicalization(e)
    }
}

impl From<bbs_plus::prelude::BBSPlusError> for RDFProofsError {
    fn from(e: bbs_plus::prelude::BBSPlusError) -> Self {
        Self::BBSPlus(e)
    }
}

impl From<ark_serialize::SerializationError> for RDFProofsError {
    fn from(e: ark_serialize::SerializationError) -> Self {
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

impl From<oxiri::IriParseError> for RDFProofsError {
    fn from(e: oxiri::IriParseError) -> Self {
        Self::IriParse(e)
    }
}

impl From<oxrdf::BlankNodeIdParseError> for RDFProofsError {
    fn from(e: oxrdf::BlankNodeIdParseError) -> Self {
        Self::BlankNodeIdParse(e)
    }
}

impl From<oxrdf::LanguageTagParseError> for RDFProofsError {
    fn from(e: oxrdf::LanguageTagParseError) -> Self {
        Self::LanguageTagParse(e)
    }
}

impl From<proof_system::prelude::ProofSystemError> for RDFProofsError {
    fn from(e: proof_system::prelude::ProofSystemError) -> Self {
        Self::ProofSystem(e)
    }
}

impl From<oxttl::ParseError> for RDFProofsError {
    fn from(e: oxttl::ParseError) -> Self {
        Self::TtlParse(e)
    }
}

impl From<regex::Error> for RDFProofsError {
    fn from(e: regex::Error) -> Self {
        Self::InvalidDeanonMapFormat(e.to_string())
    }
}
