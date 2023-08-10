use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;

pub mod common;
pub mod context;
pub mod error;
pub mod keygen;
pub mod loader;
pub mod proof;
pub mod signature;
pub mod vc;
pub mod constants {
    pub const CRYPTOSUITE_SIGN: &str = "bbs-termwise-signature-2023";
    pub const CRYPTOSUITE_PROOF: &str = "bbs-termwise-proof-2023";
    pub const NYM_IRI_PREFIX: &str = "urn:nym:";
    pub const GENERATOR_SEED: &[u8; 28] = b"BBS_*_MESSAGE_GENERATOR_SEED"; // TODO: fix it later
    pub const MAP_TO_SCALAR_AS_HASH_DST: &[u8; 32] = b"BBS_*_MAP_MSG_TO_SCALAR_AS_HASH_"; // TODO: fix it later
    pub const DELIMITER: &[u8; 13] = b"__DELIMITER__"; // TODO: fix it later
}

type Fr = <Bls12_381 as Pairing>::ScalarField;

#[cfg(test)]
mod tests {
    use crate::{context::PROOF_VALUE, vc::VerifiableCredential};
    use ark_bls12_381::Bls12_381;
    use ark_serialize::CanonicalDeserialize;
    use bbs_plus::prelude::SignatureG1 as BBSSignatureG1;
    use oxrdf::{Graph, TermRef};
    use oxttl::NTriplesParser;
    use std::io::Cursor;

    pub(crate) const DOCUMENT_LOADER_NTRIPLES: &str = r#"
# issuer0
<did:example:issuer0> <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
<did:example:issuer0#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
<did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer0> .
<did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "uekl-7abY7R84yTJEJ6JRqYohXxPZPDoTinJ7XCcBkmk" .
<did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "ukiiQxfsSfV0E2QyBlnHTK2MThnd7_-Fyf6u76BUd24uxoDF4UjnXtxUo8b82iuPZBOa8BXd1NpE20x3Rfde9udcd8P8nPVLr80Xh6WLgI9SYR6piNzbHhEVIfgd_Vo9P" .
# issuer1
<did:example:issuer1> <https://w3id.org/security#verificationMethod> <did:example:issuer1#bls12_381-g2-pub001> .
<did:example:issuer1#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
<did:example:issuer1#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer1> .
<did:example:issuer1#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "uQkpZn0SW42c2tlYa0IIFXyabAYHbwc0z3l_GvXQbWSg" .
<did:example:issuer1#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "usFM3CcvBMl_Dg5ixhQkHKGdqzY3GU9Uck6lj2i8vpbzLFOiZnjDNOpsItrkbNf2iCku-SZu5kO3nbLis-fuRhz_QwFcKw9IBpbPRPwXNQTX3zzcFsoNzs_wo8tkLQlcS" .
"#;

    pub(crate) fn get_graph_from_ntriples_str(ntriples: &str) -> Graph {
        Graph::from_iter(
            NTriplesParser::new()
                .parse_from_read(Cursor::new(ntriples))
                .into_iter()
                .map(|x| x.unwrap()),
        )
    }

    pub(crate) fn print_vc(vc: &VerifiableCredential) {
        println!("signed vc:");
        println!("document:");
        for t in &vc.document {
            println!("{}", t);
        }
        println!("proof:");
        for t in &vc.proof {
            println!("{}", t);
        }
        println!("");
    }

    pub(crate) fn print_signature(vc: &VerifiableCredential) {
        let proof_value_triple = vc.proof.triples_for_predicate(PROOF_VALUE).next().unwrap();
        if let TermRef::Literal(v) = proof_value_triple.object {
            let proof_value = v.value();
            let (_, proof_value_bytes) = multibase::decode(proof_value).unwrap();
            let signature =
                BBSSignatureG1::<Bls12_381>::deserialize_compressed(&*proof_value_bytes).unwrap();
            println!("decoded signature:\n{:#?}\n", signature);
        }
    }
}
