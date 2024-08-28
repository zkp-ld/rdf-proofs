use crate::{
    common::{multibase_with_codec_to_ark, BBSPlusPublicKey, BBSPlusSecretKey},
    context::{PUBLIC_KEY_MULTIBASE, SECRET_KEY_MULTIBASE, VERIFICATION_METHOD},
    error::RDFProofsError,
};
use oxrdf::{dataset::GraphView, Graph, NamedNodeRef, TermRef, Triple, TripleRef};

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
    ) -> Graph {
        Graph::from_iter(
            self.inner
                .triples_for_subject(verification_method_identifier),
        )
    }

    pub fn get_secret_key(
        &self,
        verification_method_identifier: NamedNodeRef,
    ) -> Result<BBSPlusSecretKey, RDFProofsError> {
        let verification_method = self.retrieve_verification_method(verification_method_identifier);

        let secret_key_term = verification_method
            .object_for_subject_predicate(verification_method_identifier, SECRET_KEY_MULTIBASE)
            .ok_or(RDFProofsError::VerificationMethodNotFound)?;
        let secret_key_multibase = match secret_key_term {
            TermRef::Literal(v) => v.value(),
            _ => return Err(RDFProofsError::InvalidVerificationMethodKey),
        };
        let (_codec, secret_key) = multibase_with_codec_to_ark(secret_key_multibase)
            .map_err(|_| RDFProofsError::InvalidVerificationMethodKeyCodec)?;
        // TODO: check codec

        Ok(secret_key)
    }

    pub fn get_public_key(
        &self,
        verification_method_identifier: NamedNodeRef,
    ) -> Result<BBSPlusPublicKey, RDFProofsError> {
        let verification_method = self.retrieve_verification_method(verification_method_identifier);

        let public_key_term = verification_method
            .object_for_subject_predicate(verification_method_identifier, PUBLIC_KEY_MULTIBASE)
            .ok_or(RDFProofsError::VerificationMethodNotFound)?;
        let public_key_multibase = match public_key_term {
            TermRef::Literal(v) => v.value(),
            _ => return Err(RDFProofsError::InvalidVerificationMethodKey),
        };
        let (_codec, public_key) = multibase_with_codec_to_ark(public_key_multibase)
            .map_err(|_| RDFProofsError::InvalidVerificationMethodKeyCodec)?;
        // TODO: check codec

        Ok(public_key)
    }

    pub fn get_public_key_from_proof_graph(
        &self,
        proof_graph: &Graph,
    ) -> Result<BBSPlusPublicKey, RDFProofsError> {
        let vm_triple = proof_graph
            .triples_for_predicate(VERIFICATION_METHOD)
            .next()
            .ok_or(RDFProofsError::VerificationMethodNotFoundInProof)?;
        self.get_public_key_from_vm_triple(vm_triple)
    }

    pub fn get_public_key_from_proof_graph_view(
        &self,
        proof_graph: &GraphView,
    ) -> Result<BBSPlusPublicKey, RDFProofsError> {
        let vm_triple = proof_graph
            .triples_for_predicate(VERIFICATION_METHOD)
            .next()
            .ok_or(RDFProofsError::VerificationMethodNotFoundInProof)?;
        self.get_public_key_from_vm_triple(vm_triple)
    }

    fn get_public_key_from_vm_triple(
        &self,
        vm_triple: TripleRef,
    ) -> Result<BBSPlusPublicKey, RDFProofsError> {
        let verification_method_identifier = match vm_triple.object {
            TermRef::NamedNode(v) => Ok(v),
            _ => Err(RDFProofsError::InvalidVerificationMethodURL),
        }?;
        self.get_public_key(verification_method_identifier)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{ark_to_base58btc, get_graph_from_ntriples};
    use oxrdf::NamedNode;

    const KEY_GRAPH: &str = r#"
    # issuer0
    <did:example:issuer0> <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
    <did:example:issuer0#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
    <did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer0> .
    <did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "z4893E1L7AeYfqaduUdLYgcxefWAah8gJB8RhPi7JHQkdRbe" .
    <did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "zUC77BjGcGDVWfBdgzqwzp3uuWkoWuRMe8pnx4dkncia5t9LKHVt96BPGBizeSU7BKiV35h1tsuVwHUVt4arZuckxGCb2tTsB3fsY66mQNs5Bwoac2w2iyYFe8uenBUYdAiveEr" .
    # issuer1
    <did:example:issuer1> <https://w3id.org/security#verificationMethod> <did:example:issuer1#bls12_381-g2-pub001> .
    <did:example:issuer1#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
    <did:example:issuer1#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer1> .
    <did:example:issuer1#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "z488yTRFj1e7W6s6MVN6iYm6taiNByQwSCg2XwgEJvAcXr15" .
    <did:example:issuer1#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "zUC7HaSjNELSGG8QnYdMvNurgfWfdGNo1Znqds6CoYQ24qKKWogiLtKWPoCLJapEYdKAMN9r6bdF9MeNrfV3fhUzkKwrfUewD5yVhwSVpM4tjv87YVgWGRTUuesxf7scabbPAnD" .
    # issuer2
    <did:example:issuer2> <https://w3id.org/security#verificationMethod> <did:example:issuer2#bls12_381-g2-pub001> .
    <did:example:issuer2#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
    <did:example:issuer2#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer2> .
    <did:example:issuer2#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "z489AEiC5VbeLmVZxokiJYkXNZrMza9eCiPZ51ekgcV9mNvG" .
    <did:example:issuer2#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "zUC7DKvfSfydgg48FpP53HgsLfWrVHfrmUXbwvw8AnSgW1JiA5741mwe3hpMNNRMYh3BgR9ebxvGAxPxFhr8F3jQHZANqb3if2MycjQN3ZBSWP3aGoRyat294icdVMDhTqoKXeJ" .
    # issuer3
    <did:example:issuer3> <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> .
    <did:example:issuer3#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
    <did:example:issuer3#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer3> .
    <did:example:issuer3#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "z488w754KqucDkNxCWCoi5DkH6pvEt6aNZNYYYoKmDDx8m5G" .
    <did:example:issuer3#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "zUC74KLKQtdApVyY3EbAZfiW6A7HdwSZVLsBF2vs5512YwNWs5PRYiqavzWLoiAq6UcKLv6RAnUM9Y117Pg4LayaBMa9euz23C2TDtBq8QuhpbDRDqsjUxLS5S9ruWRk71SEo69" .
    "#;

    #[test]
    fn get_keypair() {
        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();

        let verification_method_identifier =
            NamedNode::new("did:example:issuer0#bls12_381-g2-pub001").unwrap();
        let (secret_key, public_key) = key_graph
            .get_keypair((&verification_method_identifier).into())
            .expect("Failed to get keypair");

        let secret_key_multibase =
            ark_to_base58btc(&secret_key, crate::common::Multicodec::Bls12381G2Priv).unwrap();
        assert_eq!(
            secret_key_multibase,
            "z4893E1L7AeYfqaduUdLYgcxefWAah8gJB8RhPi7JHQkdRbe"
        );

        let public_key_multibase =
            ark_to_base58btc(&public_key, crate::common::Multicodec::Bls12381G2Pub).unwrap();
        assert_eq!(
            public_key_multibase,
            "zUC77BjGcGDVWfBdgzqwzp3uuWkoWuRMe8pnx4dkncia5t9LKHVt96BPGBizeSU7BKiV35h1tsuVwHUVt4arZuckxGCb2tTsB3fsY66mQNs5Bwoac2w2iyYFe8uenBUYdAiveEr"
        );
    }

    #[test]
    fn verification_method_not_found() {
        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();

        let verification_method_identifier =
            NamedNode::new("did:example:unknown-unknown-unknown").unwrap();
        let result = key_graph.get_keypair((&verification_method_identifier).into());
        assert!(matches!(
            result,
            Err(RDFProofsError::VerificationMethodNotFound)
        ));
    }

    #[test]
    fn verification_method_not_found_in_proof() {
        const INVALID_PROOF: &str = r#"
        _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
        _:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
        _:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
        # verification method does not exist
        "#;

        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();
        let proof_graph: Graph = get_graph_from_ntriples(INVALID_PROOF).unwrap().into();
        let result = key_graph.get_public_key_from_proof_graph(&proof_graph);

        assert!(matches!(
            result,
            Err(RDFProofsError::VerificationMethodNotFoundInProof)
        ));
    }

    #[test]
    fn invalid_verification_method_url() {
        const INVALID_PROOF: &str = r#"
        _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
        _:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
        _:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
        _:b0 <https://w3id.org/security#verificationMethod> _:b0 .  # invalid URL
        "#;

        let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();
        let proof_graph: Graph = get_graph_from_ntriples(INVALID_PROOF).unwrap().into();
        let result = key_graph.get_public_key_from_proof_graph(&proof_graph);

        assert!(matches!(
            result,
            Err(RDFProofsError::InvalidVerificationMethodURL)
        ));
    }

    #[test]
    fn invalid_verification_method_secret_key() {
        const INVALID_KEY_GRAPH: &str = r#"
        <did:example:issuer0> <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
        <did:example:issuer0#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
        <did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer0> .
        <did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> _:b0 .  # invalid key
        <did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "zUC77BjGcGDVWfBdgzqwzp3uuWkoWuRMe8pnx4dkncia5t9LKHVt96BPGBizeSU7BKiV35h1tsuVwHUVt4arZuckxGCb2tTsB3fsY66mQNs5Bwoac2w2iyYFe8uenBUYdAiveEr" .
        "#;

        let key_graph: KeyGraph = get_graph_from_ntriples(INVALID_KEY_GRAPH).unwrap().into();

        let verification_method_identifier =
            NamedNode::new("did:example:issuer0#bls12_381-g2-pub001").unwrap();
        let result = key_graph.get_keypair((&verification_method_identifier).into());
        assert!(matches!(
            result,
            Err(RDFProofsError::InvalidVerificationMethodKey)
        ));
    }

    #[test]
    fn invalid_verification_method_public_key() {
        const INVALID_KEY_GRAPH: &str = r#"
        <did:example:issuer0> <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
        <did:example:issuer0#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
        <did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer0> .
        <did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "z4893E1L7AeYfqaduUdLYgcxefWAah8gJB8RhPi7JHQkdRbe" .
        <did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> _:b0 .  # invalid key
        "#;

        let key_graph: KeyGraph = get_graph_from_ntriples(INVALID_KEY_GRAPH).unwrap().into();

        let verification_method_identifier =
            NamedNode::new("did:example:issuer0#bls12_381-g2-pub001").unwrap();
        let result = key_graph.get_keypair((&verification_method_identifier).into());
        assert!(matches!(
            result,
            Err(RDFProofsError::InvalidVerificationMethodKey)
        ));
    }

    #[test]
    fn invalid_verification_method_codec_secret_key() {
        const INVALID_KEY_GRAPH: &str = r#"
        <did:example:issuer0> <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
        <did:example:issuer0#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
        <did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer0> .
        <did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "z9993E1L7AeYfqaduUdLYgcxefWAah8gJB8RhPi7JHQkdRbe" .  # invalid codec
        <did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "zUC77BjGcGDVWfBdgzqwzp3uuWkoWuRMe8pnx4dkncia5t9LKHVt96BPGBizeSU7BKiV35h1tsuVwHUVt4arZuckxGCb2tTsB3fsY66mQNs5Bwoac2w2iyYFe8uenBUYdAiveEr" .
        "#;

        let key_graph: KeyGraph = get_graph_from_ntriples(INVALID_KEY_GRAPH).unwrap().into();

        let verification_method_identifier =
            NamedNode::new("did:example:issuer0#bls12_381-g2-pub001").unwrap();
        let result = key_graph.get_keypair((&verification_method_identifier).into());
        assert!(matches!(
            result,
            Err(RDFProofsError::InvalidVerificationMethodKeyCodec)
        ));
    }

    #[test]
    fn invalid_verification_method_codec_public_key() {
        const INVALID_KEY_GRAPH: &str = r#"
        <did:example:issuer0> <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
        <did:example:issuer0#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
        <did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer0> .
        <did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "z4893E1L7AeYfqaduUdLYgcxefWAah8gJB8RhPi7JHQkdRbe" .
        <did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "z9977BjGcGDVWfBdgzqwzp3uuWkoWuRMe8pnx4dkncia5t9LKHVt96BPGBizeSU7BKiV35h1tsuVwHUVt4arZuckxGCb2tTsB3fsY66mQNs5Bwoac2w2iyYFe8uenBUYdAiveEr" .  # invalid codec
        "#;

        let key_graph: KeyGraph = get_graph_from_ntriples(INVALID_KEY_GRAPH).unwrap().into();

        let verification_method_identifier =
            NamedNode::new("did:example:issuer0#bls12_381-g2-pub001").unwrap();
        let result = key_graph.get_keypair((&verification_method_identifier).into());
        assert!(matches!(
            result,
            Err(RDFProofsError::InvalidVerificationMethodKeyCodec)
        ));
    }
}
