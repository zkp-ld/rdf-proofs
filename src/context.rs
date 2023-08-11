use oxrdf::NamedNodeRef;

pub const CREATED: NamedNodeRef = NamedNodeRef::new_unchecked("http://purl.org/dc/terms/created");
pub const VERIFIABLE_CREDENTIAL_TYPE: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://www.w3.org/2018/credentials#VerifiableCredential");
pub const VERIFIABLE_PRESENTATION_TYPE: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://www.w3.org/2018/credentials#VerifiablePresentation");
pub const VERIFIABLE_CREDENTIAL: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://www.w3.org/2018/credentials#verifiableCredential");
pub const DATA_INTEGRITY_PROOF: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://w3id.org/security#DataIntegrityProof");
pub const PROOF: NamedNodeRef = NamedNodeRef::new_unchecked("https://w3id.org/security#proof");
pub const CRYPTOSUITE: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://w3id.org/security#cryptosuite");
pub const PROOF_PURPOSE: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://w3id.org/security#proofPurpose");
pub const PROOF_VALUE: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://w3id.org/security#proofValue");
pub const VERIFICATION_METHOD: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://w3id.org/security#verificationMethod");
pub const ASSERTION_METHOD: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://w3id.org/security#assertionMethod");
pub const FILTER: NamedNodeRef = NamedNodeRef::new_unchecked("https://zkp-ld.org/security#filter");
pub const PUBLIC_KEY_MULTIBASE: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://w3id.org/security#publicKeyMultibase");
pub const SECRET_KEY_MULTIBASE: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://w3id.org/security#secretKeyMultibase");
pub const MULTIBASE: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://w3id.org/security#multibase");
