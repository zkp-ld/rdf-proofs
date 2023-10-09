use oxrdf::NamedNodeRef;

// http://purl.org/dc/terms/
pub const CREATED: NamedNodeRef = NamedNodeRef::new_unchecked("http://purl.org/dc/terms/created");

// https://www.w3.org/2018/credentials#
pub const VERIFIABLE_CREDENTIAL_TYPE: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://www.w3.org/2018/credentials#VerifiableCredential");
pub const VERIFIABLE_PRESENTATION_TYPE: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://www.w3.org/2018/credentials#VerifiablePresentation");
pub const VERIFIABLE_CREDENTIAL: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://www.w3.org/2018/credentials#verifiableCredential");
pub const HOLDER: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://www.w3.org/2018/credentials#holder");

// https://w3id.org/security#
pub const DATA_INTEGRITY_PROOF: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://w3id.org/security#DataIntegrityProof");
pub const PROOF: NamedNodeRef = NamedNodeRef::new_unchecked("https://w3id.org/security#proof");
pub const CHALLENGE: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://w3id.org/security#challenge");
pub const DOMAIN: NamedNodeRef = NamedNodeRef::new_unchecked("https://w3id.org/security#domain");
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
pub const AUTHENTICATION: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://w3id.org/security#authenticationMethod");
pub const PUBLIC_KEY_MULTIBASE: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://w3id.org/security#publicKeyMultibase");
pub const SECRET_KEY_MULTIBASE: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://w3id.org/security#secretKeyMultibase");
pub const MULTIBASE: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://w3id.org/security#multibase");

// https://zkp-ld.org/security#
pub const SECRET_COMMITMENT: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://zkp-ld.org/security#secretCommitment");
pub const FILTER: NamedNodeRef = NamedNodeRef::new_unchecked("https://zkp-ld.org/security#filter");
pub const PREDICATE: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://zkp-ld.org/security#predicate");
pub const PREDICATE_TYPE: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://zkp-ld.org/security#Predicate");
pub const CIRCUIT: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://zkp-ld.org/security#circuit");
pub const PRIVATE: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://zkp-ld.org/security#private");
pub const PUBLIC: NamedNodeRef = NamedNodeRef::new_unchecked("https://zkp-ld.org/security#public");
pub const PRIVATE_VARIABLE: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://zkp-ld.org/security#PrivateVariable");
pub const PUBLIC_VARIABLE: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://zkp-ld.org/security#PublicVariable");
pub const PREDICATE_VAR: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://zkp-ld.org/security#var");
pub const PREDICATE_VAL: NamedNodeRef =
    NamedNodeRef::new_unchecked("https://zkp-ld.org/security#val");

// http://schema.org/
pub const SCO_DATE: NamedNodeRef = NamedNodeRef::new_unchecked("http://schema.org/Date");
pub const SCO_DATETIME: NamedNodeRef = NamedNodeRef::new_unchecked("http://schema.org/DateTime");
