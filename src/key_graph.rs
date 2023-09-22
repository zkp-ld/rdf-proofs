use crate::{
    common::{multibase_to_ark, BBSPlusPublicKey, BBSPlusSecretKey},
    context::{PUBLIC_KEY_MULTIBASE, SECRET_KEY_MULTIBASE},
    error::RDFProofsError,
};
use oxrdf::{Graph, NamedNodeRef, TermRef, Triple};

pub struct KeyGraph {
    inner: Graph,
}

impl From<Graph> for KeyGraph {
    fn from(value: Graph) -> Self {
        Self { inner: value }
    }
}

impl From<Vec<Triple>> for KeyGraph {
    fn from(value: Vec<Triple>) -> Self {
        Self {
            inner: Graph::from_iter(value),
        }
    }
}

impl KeyGraph {
    // TODO: add dereferencing external controller document URL
    pub fn retrieve_verification_method(
        &self,
        verification_method_identifier: NamedNodeRef,
    ) -> Result<Graph, RDFProofsError> {
        Ok(Graph::from_iter(
            self.inner
                .triples_for_subject(verification_method_identifier),
        ))
    }

    pub fn get_secret_key(
        &self,
        verification_method_identifier: NamedNodeRef,
    ) -> Result<BBSPlusSecretKey, RDFProofsError> {
        let verification_method =
            self.retrieve_verification_method(verification_method_identifier)?;

        let secret_key_term = verification_method
            .object_for_subject_predicate(verification_method_identifier, SECRET_KEY_MULTIBASE)
            .ok_or(RDFProofsError::InvalidVerificationMethod)?;
        let secret_key_multibase = match secret_key_term {
            TermRef::Literal(v) => v.value(),
            _ => return Err(RDFProofsError::InvalidVerificationMethod),
        };
        let secret_key = multibase_to_ark(secret_key_multibase)?;
        Ok(secret_key)
    }

    pub fn get_public_key(
        &self,
        verification_method_identifier: NamedNodeRef,
    ) -> Result<BBSPlusPublicKey, RDFProofsError> {
        let verification_method =
            self.retrieve_verification_method(verification_method_identifier)?;

        let public_key_term = verification_method
            .object_for_subject_predicate(verification_method_identifier, PUBLIC_KEY_MULTIBASE)
            .ok_or(RDFProofsError::InvalidVerificationMethod)?;
        let public_key_multibase = match public_key_term {
            TermRef::Literal(v) => v.value(),
            _ => return Err(RDFProofsError::InvalidVerificationMethod),
        };
        let public_key = multibase_to_ark(public_key_multibase)?;
        Ok(public_key)
    }

    pub fn get_keypair(
        &self,
        verification_method_identifier: NamedNodeRef,
    ) -> Result<(BBSPlusSecretKey, BBSPlusPublicKey), RDFProofsError> {
        let secret_key = self.get_secret_key(verification_method_identifier)?;
        let public_key = self.get_public_key(verification_method_identifier)?;
        Ok((secret_key, public_key))
    }
}
