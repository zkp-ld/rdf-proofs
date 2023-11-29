use crate::common::{BBSPlusHash, Fr, PedersenCommitmentStmt, Proof, Statements};
use crate::constants::BLIND_SIG_REQUEST_CONTEXT;
use crate::error::RDFProofsError;
use ark_bls12_381::{G1Affine, G1Projective};
use ark_crypto_primitives::encryption::elgamal::{
    Ciphertext, ElGamal, Parameters, PublicKey, Randomness, SecretKey,
};
use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
use ark_std::rand::RngCore;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ark_std::UniformRand;

use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use proof_system::meta_statement::MetaStatements;
use proof_system::proof_spec::ProofSpec;
use proof_system::witness::{Witness, Witnesses};

pub type Bls12381ElGamal = ElGamal<G1Projective>;
pub type ElGamalPublicKey = PublicKey<G1Projective>;
pub type ElGamalSecretKey = SecretKey<G1Projective>;
pub type ElGamalCiphertext = Ciphertext<G1Projective>;
pub type ElGamalParams = Parameters<G1Projective>;
pub struct ElGamalVerifiableEncryption {
    pub cipher_text: ElGamalCiphertext,
    pub pok_for_commitment: Proof,
}

pub fn elliptic_elgamal_keygen<R: RngCore>(
    rng: &mut R,
) -> Result<(ElGamalPublicKey, ElGamalSecretKey), RDFProofsError> {
    let mut param_rnd = StdRng::seed_from_u64(0u64);
    let params = Bls12381ElGamal::setup(&mut param_rnd).unwrap();

    let (pk, sk) = Bls12381ElGamal::keygen(&params, rng).unwrap();

    Ok((pk, sk))
}

pub fn elliptic_elgamal_encrypt<R: RngCore>(
    pk: &ElGamalPublicKey,
    msg: &G1Affine,
    rng: &mut R,
) -> Result<ElGamalCiphertext, RDFProofsError> {
    let mut param_rnd = StdRng::seed_from_u64(0u64);
    let params = Bls12381ElGamal::setup(&mut param_rnd).unwrap();

    let r = Randomness::rand(rng);

    let (c1, c2) = Bls12381ElGamal::encrypt(&params, &pk, &msg, &r).unwrap();
    Ok((c1, c2))
}

pub fn elliptic_elgamal_decrypt(
    sk: &ElGamalSecretKey,
    cipher: &ElGamalCiphertext,
) -> Result<G1Affine, RDFProofsError> {
    let mut param_rnd = StdRng::seed_from_u64(0u64);
    let params = Bls12381ElGamal::setup(&mut param_rnd).unwrap();

    let msg = Bls12381ElGamal::decrypt(&params, &sk, &cipher).unwrap();
    Ok(msg)
}

pub fn elliptic_elgamal_verifiable_encryption_with_bbs_plus<R: RngCore>(
    pk: &ElGamalPublicKey,
    hd_hat: &G1Affine,
    uid: &Fr,
    challenge: &str,
    rng: &mut R,
) -> Result<ElGamalVerifiableEncryption, RDFProofsError> {
    let mut param_rnd = StdRng::seed_from_u64(0u64);
    let params: ElGamalParams = Bls12381ElGamal::setup(&mut param_rnd).unwrap();

    let g0 = params.generator;
    let r: Fr = Fr::rand(rng);

    // e1 = g0 * r
    let e1 = g0.mul_bigint(r.into_bigint());
    // e2 = hd_hat * uid + g0 * r
    let e2 = hd_hat.mul_bigint(uid.into_bigint()) + pk.mul_bigint(r.into_bigint());

    let mut statements = Statements::new();

    statements.add(PedersenCommitmentStmt::new_statement_from_params(
        vec![g0],
        e1.into(),
    ));
    statements.add(PedersenCommitmentStmt::new_statement_from_params(
        vec![*hd_hat, *pk],
        e2.into(),
    ));
    // TODO: fix context
    let context = Some(BLIND_SIG_REQUEST_CONTEXT.to_vec());
    let proof_spec = ProofSpec::new(statements, MetaStatements::new(), vec![], context);
    proof_spec.validate()?;
    let mut witnesses = Witnesses::new();
    witnesses.add(Witness::PedersenCommitment([r].to_vec()));
    witnesses.add(Witness::PedersenCommitment([*uid, r].to_vec()));

    let challenge = Option::from(challenge.as_bytes().to_vec());

    let pok_for_commitment =
        Proof::new::<R, BBSPlusHash>(rng, proof_spec, witnesses, challenge, Default::default())?.0;

    Ok(ElGamalVerifiableEncryption {
        cipher_text: (e1.into(), e2.into()),
        pok_for_commitment,
    })
}

pub fn verify_elliptic_elgamal_verifiable_encryption_with_bbs_plus<R: RngCore>(
    pk: &ElGamalPublicKey,
    hd_hat: &G1Affine,
    cipher_text: &ElGamalCiphertext,
    pok_for_commitment: Proof,
    challenge: &str,
    rng: &mut R,
) -> Result<(), RDFProofsError> {
    let mut param_rnd = StdRng::seed_from_u64(0u64);
    let params: ElGamalParams = Bls12381ElGamal::setup(&mut param_rnd).unwrap();

    let g0 = params.generator;
    let (e1, e2) = cipher_text;

    let mut statements = Statements::new();
    statements.add(PedersenCommitmentStmt::new_statement_from_params(
        vec![g0],
        *e1,
    ));
    statements.add(PedersenCommitmentStmt::new_statement_from_params(
        vec![*hd_hat, *pk],
        *e2,
    ));
    // TODO: fix context
    let context = Some(BLIND_SIG_REQUEST_CONTEXT.to_vec());
    let proof_spec = ProofSpec::new(statements, MetaStatements::new(), vec![], context);
    let challenge = Option::from(challenge.as_bytes().to_vec());
    Ok(pok_for_commitment.verify::<R, BBSPlusHash>(
        rng,
        proof_spec,
        challenge,
        Default::default(),
    )?)
}

#[cfg(test)]
mod tests {
    use crate::error::RDFProofsError;
    use crate::{
        common::{BBSPlusHash, Fr},
        elliptic_elgamal::{
            elliptic_elgamal_decrypt, elliptic_elgamal_encrypt, elliptic_elgamal_keygen,
            elliptic_elgamal_verifiable_encryption_with_bbs_plus,
            verify_elliptic_elgamal_verifiable_encryption_with_bbs_plus,
        },
    };
    use ark_bls12_381::G1Affine;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use ark_std::UniformRand;
    use dock_crypto_utils::hashing_utils::projective_group_elem_from_try_and_incr;

    use ark_ec::AffineRepr;
    use ark_ff::PrimeField;

    pub fn hash_str_to_affine(payload: &str) -> Result<G1Affine, RDFProofsError> {
        let message =
            projective_group_elem_from_try_and_incr::<G1Affine, BBSPlusHash>(payload.as_bytes());
        Ok(message.into())
    }

    #[test]
    fn test_elgamal() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let (pk, sk) = elliptic_elgamal_keygen(&mut rng).unwrap();
        println!("pk: {:?}", pk);

        let message = "PlainMessage";
        let m_affine = hash_str_to_affine(message).unwrap();

        let c = elliptic_elgamal_encrypt(&pk, &m_affine, &mut rng).unwrap();

        let m = elliptic_elgamal_decrypt(&sk, &c).unwrap();

        println!("message: {:?}", m_affine);
        println!("c: {:?}", c);
        println!("m: {:?}", m);

        assert_eq!(m_affine, m)
    }

    #[test]
    fn test_elliptic_elgamal_verifiable_encryption_with_bbs_plus() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let (pk, sk) = elliptic_elgamal_keygen(&mut rng).unwrap();

        let uid: Fr = Fr::rand(&mut rng);
        let hd_hat = G1Affine::rand(&mut rng);

        let res = elliptic_elgamal_verifiable_encryption_with_bbs_plus(
            &pk,
            &hd_hat,
            &uid,
            "CHALLENGE",
            &mut rng,
        )
        .unwrap();
        println!("pok_for_commitment: {:?}", res.pok_for_commitment);

        verify_elliptic_elgamal_verifiable_encryption_with_bbs_plus(
            &pk,
            &hd_hat,
            &res.cipher_text,
            res.pok_for_commitment,
            "CHALLENGE",
            &mut rng,
        )
        .unwrap();

        let decrypted_value = elliptic_elgamal_decrypt(&sk, &res.cipher_text).unwrap();
        assert_eq!(decrypted_value, hd_hat.mul_bigint(uid.into_bigint()));
    }

    #[test]
    fn test_wrong_challenge_elliptic_elgamal_verifiable_encryption_with_bbs_plus() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let (pk, _sk) = elliptic_elgamal_keygen(&mut rng).unwrap();

        let uid: Fr = Fr::rand(&mut rng);
        let hd_hat = G1Affine::rand(&mut rng);

        let res = elliptic_elgamal_verifiable_encryption_with_bbs_plus(
            &pk,
            &hd_hat,
            &uid,
            "CHALLENGE",
            &mut rng,
        )
        .unwrap();

        let res = verify_elliptic_elgamal_verifiable_encryption_with_bbs_plus(
            &pk,
            &hd_hat,
            &res.cipher_text,
            res.pok_for_commitment,
            "WRONG_CHALLENGE",
            &mut rng,
        );
        assert!(res.is_err());
    }
}
