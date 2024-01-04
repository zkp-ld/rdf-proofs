use crate::common::Fr;
use crate::error::RDFProofsError;
use ark_std::rand::RngCore;
use ark_std::UniformRand;

pub type ElGamalPublicKey = (Fr, Fr);
pub type ElGamalSecretKey = Fr;
pub type ElGamalCiphertext = (Fr, Fr);

pub fn elgamal_keygen<R: RngCore>(
    rng: &mut R,
) -> Result<(ElGamalPublicKey, ElGamalSecretKey), RDFProofsError> {
    let x0 = Fr::rand(rng);
    let g0 = Fr::rand(rng);
    let y = x0 * g0;
    let (sk, pk) = (x0, (g0, y));
    Ok((pk, sk))
}

pub fn elgamal_encrypt<R: RngCore>(
    pk: &ElGamalPublicKey,
    msg: &Fr,
    rng: &mut R,
) -> Result<ElGamalCiphertext, RDFProofsError> {
    let r = Fr::rand(rng);
    let (g0, y) = pk;
    let c1 = r * g0;
    let c2 = r * y + msg;
    Ok((c1, c2))
}

pub fn elgamal_decrypt(
    sk: ElGamalSecretKey,
    cipher: ElGamalCiphertext,
) -> Result<Fr, RDFProofsError> {
    let (c1, c2) = cipher;
    let msg = c2 - sk * c1;
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use crate::{
        common::{get_hasher, hash_byte_to_field},
        elgamal::{elgamal_decrypt, elgamal_encrypt, elgamal_keygen},
    };
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_elgamal() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let (pk, sk) = elgamal_keygen(&mut rng).unwrap();

        let hasher = get_hasher();
        let msg = hash_byte_to_field(b"PLAINTEXT", &hasher).unwrap();

        let ciher_text = elgamal_encrypt(&pk, &msg, &mut rng).unwrap();
        println!("cipher text: {:?}", ciher_text);

        let decrypted_msg = elgamal_decrypt(sk, ciher_text).unwrap();

        assert_eq!(decrypted_msg, msg);
    }
}
