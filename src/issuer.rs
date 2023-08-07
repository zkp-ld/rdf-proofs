use crate::{context::PROOF_VALUE, error::SignError, vc::VerifiableCredential};
use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{prelude::StdRng, SeedableRng};
use bbs_plus::prelude::{
    KeypairG2 as BBSKeyPairG2, PublicKeyG2 as BBSPublicKeyG2, SignatureG1 as BBSSignatureG1,
    SignatureParamsG1 as BBSSignatureParamsG1,
};
use blake2::Blake2b512;
use multibase::Base;
use oxrdf::{vocab, Graph, Literal, Term, Triple};
use proof_system::{
    setup_params::SetupParams::BBSPlusSignatureParams,
    statement::{bbs_plus::PoKBBSSignatureG1 as PoKBBSSignatureG1Stmt, Statements},
    witness::PoKBBSSignatureG1 as PoKBBSSignatureG1Wit,
};
use rdf_canon::{issue_graph, relabel_graph, sort_graph};

const GENERATOR_SEED: &[u8; 28] = b"BBS_*_MESSAGE_GENERATOR_SEED"; // TODO: fix it later
const MAP_TO_SCALAR_AS_HASH_DST: &[u8; 32] = b"BBS_*_MAP_MSG_TO_SCALAR_AS_HASH_"; // TODO: fix it later
const DELIMITER: &[u8; 13] = b"__DELIMITER__"; // TODO: fix it later

type Fr = <Bls12_381 as Pairing>::ScalarField;

pub fn sign(unsecured_credential: &mut VerifiableCredential) -> Result<(), SignError> {
    let VerifiableCredential { document, proof } = unsecured_credential;
    let transformed_document = transform(document)?;
    let canonical_proof_config = configure_proof(proof)?;
    let hash_data = hash(&transformed_document, &canonical_proof_config)?;
    let proof_value = serialize_proof(&hash_data, proof)?;
    add_proof_value(unsecured_credential, proof_value)?;
    Ok(())
}

fn transform(unsecured_document: &Graph) -> Result<Vec<Term>, SignError> {
    let issued_identifiers_map = &issue_graph(unsecured_document)?;
    let canonicalized_graph = relabel_graph(unsecured_document, issued_identifiers_map)?;
    let canonicalized_triples = sort_graph(&canonicalized_graph);
    Ok(canonicalized_triples
        .into_iter()
        .flat_map(|t| vec![t.subject.into(), t.predicate.into(), t.object])
        .collect())
}

fn configure_proof(proof_options: &Graph) -> Result<Vec<Term>, SignError> {
    // TODO: validate options

    transform(proof_options)
}

fn hash(
    transformed_document: &Vec<Term>,
    canonical_proof_config: &Vec<Term>,
) -> Result<Vec<Fr>, SignError> {
    let hasher =
        <DefaultFieldHasher<Blake2b512> as HashToField<Fr>>::new(MAP_TO_SCALAR_AS_HASH_DST);

    let mut hashed_document = hash_terms_to_field(transformed_document, &hasher)?;
    let mut hashed_proof = hash_terms_to_field(canonical_proof_config, &hasher)?;
    let delimiter: Fr = hasher
        .hash_to_field(DELIMITER, 1)
        .pop()
        .ok_or(SignError::HashToFieldError)?;

    hashed_document.push(delimiter);
    hashed_document.append(&mut hashed_proof);
    Ok(hashed_document)
}

fn hash_terms_to_field(
    terms: &Vec<Term>,
    hasher: &DefaultFieldHasher<Blake2b512>,
) -> Result<Vec<Fr>, SignError> {
    terms
        .iter()
        .map(|term| {
            hasher
                .hash_to_field(term.to_string().as_bytes(), 1)
                .pop()
                .ok_or(SignError::HashToFieldError)
        })
        .collect()
}

fn serialize_proof(hash_data: &Vec<Fr>, proof_options: &Graph) -> Result<String, SignError> {
    let mut rng = StdRng::seed_from_u64(0u64); // TODO: to be fixed

    let message_count = hash_data.len();

    // TODO: get secret key according to proof_options
    let params =
        BBSSignatureParamsG1::<Bls12_381>::new::<Blake2b512>(GENERATOR_SEED, message_count);
    let keypair = BBSKeyPairG2::<Bls12_381>::generate_using_rng(&mut rng, &params);

    let signature =
        BBSSignatureG1::<Bls12_381>::new(&mut rng, hash_data, &keypair.secret_key, &params)?;

    let mut signature_bytes = Vec::new();
    signature.serialize_compressed(&mut signature_bytes)?;
    let signature_base64url = multibase::encode(Base::Base64Url, signature_bytes);

    Ok(signature_base64url)
}

fn add_proof_value(
    unsecured_credential: &mut VerifiableCredential,
    proof_value: String,
) -> Result<(), SignError> {
    let VerifiableCredential { proof, .. } = unsecured_credential;
    let proof_triple = proof
        .triples_for_predicate(vocab::rdf::TYPE)
        .next()
        .ok_or(SignError::InvalidProofOptionsError)?; // TODO: `?s rdf:type _:o` is sufficient to identify the proof subject (?s) in the proof graph?
    let proof_subject = proof_triple.subject;
    proof.insert(&Triple::new(
        proof_subject,
        PROOF_VALUE,
        Literal::new_simple_literal(proof_value),
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{context::PROOF_VALUE, error::SignError, vc::VerifiableCredential};

    use super::sign;
    use ark_bls12_381::Bls12_381;
    use ark_serialize::CanonicalDeserialize;
    use bbs_plus::prelude::SignatureG1 as BBSSignatureG1;
    use oxrdf::{Graph, TermRef};
    use oxttl::NTriplesParser;
    use std::io::Cursor;

    #[test]
    fn sign_simple() -> Result<(), SignError> {
        let unsecured_document_ntriples = r#"
_:e0 <https://www.w3.org/2018/credentials#expirationDate> "2023-12-31T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:e0 <https://www.w3.org/2018/credentials#issuanceDate> "2020-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:e0 <https://www.w3.org/2018/credentials#credentialSubject> <http://example.org/vaccine/a> .
_:e0 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer3> .
_:e0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/vaccine/a> <http://schema.org/name> "AwesomeVaccine" .
<http://example.org/vaccine/a> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccine> .
<http://example.org/vaccine/a> <http://schema.org/status> "active" .
<http://example.org/vaccine/a> <http://schema.org/manufacturer> <http://example.org/awesomeCompany> .
"#;
        let proof_config_ntriples = r#"
_:e0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:e0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:e0 <http://purl.org/dc/terms/created> "2023-01-01T01:01:01Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:e0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:e0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bbs-bls-key1> .
"#;
        let unsecured_document = Graph::from_iter(
            NTriplesParser::new()
                .parse_from_read(Cursor::new(unsecured_document_ntriples))
                .into_iter()
                .map(|x| x.unwrap()),
        );
        let proof_config = Graph::from_iter(
            NTriplesParser::new()
                .parse_from_read(Cursor::new(proof_config_ntriples))
                .into_iter()
                .map(|x| x.unwrap()),
        );
        let mut vc = VerifiableCredential::new(unsecured_document, proof_config);

        println!("unsigned vc:");
        println!("document:");
        for t in &vc.document {
            println!("{}", t);
        }
        println!("proof:");
        for t in &vc.proof {
            println!("{}", t);
        }
        println!("");

        sign(&mut vc)?;

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
        
        let proof_value_triple = vc.proof.triples_for_predicate(PROOF_VALUE).next().unwrap();
        if let TermRef::Literal(v) = proof_value_triple.object {
            let proof_value = v.value();
            let (_, proof_value_bytes) = multibase::decode(proof_value).unwrap();
            let signature =
                BBSSignatureG1::<Bls12_381>::deserialize_compressed(&*proof_value_bytes).unwrap();
            println!("decoded signature:\n{:#?}\n", signature);
        }

        Ok(())
    }
}
