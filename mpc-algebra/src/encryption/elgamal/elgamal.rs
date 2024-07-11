use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
use ark_crypto_primitives::Error;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{fields::PrimeField, UniformRand};
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;

pub struct ElGamal<C: ProjectiveCurve> {
    _group: PhantomData<C>,
}

#[derive(Clone)]
pub struct Parameters<C: ProjectiveCurve> {
    pub generator: C::Affine,
}

impl<C: ProjectiveCurve> Parameters<C> {
    pub fn new(generator: C::Affine) -> Self {
        Parameters { generator }
    }
}

pub type PublicKey<C> = <C as ProjectiveCurve>::Affine;

pub struct SecretKey<C: ProjectiveCurve>(pub C::ScalarField);

impl<C: ProjectiveCurve> SecretKey<C> {
    pub fn new(secret_key: C::ScalarField) -> Self {
        SecretKey(secret_key)
    }
}

#[derive(Clone)]
pub struct Randomness<C: ProjectiveCurve>(pub C::ScalarField);

impl<C: ProjectiveCurve> UniformRand for Randomness<C> {
    #[inline]
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Randomness(<C as ProjectiveCurve>::ScalarField::rand(rng))
    }
}

pub type Plaintext<C> = <C as ProjectiveCurve>::Affine;

pub type Ciphertext<C> = (
    <C as ProjectiveCurve>::Affine,
    <C as ProjectiveCurve>::Affine,
);

impl<C: ProjectiveCurve> AsymmetricEncryptionScheme for ElGamal<C>
where
    C::ScalarField: PrimeField,
{
    type Parameters = Parameters<C>;
    type PublicKey = PublicKey<C>;
    type SecretKey = SecretKey<C>;
    type Randomness = Randomness<C>;
    type Plaintext = Plaintext<C>;
    type Ciphertext = Ciphertext<C>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        // get a random generator
        let generator = C::rand(rng).into();

        Ok(Parameters { generator })
    }

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error> {
        // get a random element from the scalar field
        let secret_key: <C as ProjectiveCurve>::ScalarField = C::ScalarField::rand(rng);

        // compute secret_key*generator to derive the public key
        let public_key = pp.generator.mul(secret_key.into_repr()).into();

        Ok((public_key, SecretKey(secret_key)))
    }

    fn encrypt(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &Self::Plaintext,
        r: &Self::Randomness,
    ) -> Result<Self::Ciphertext, Error> {
        // compute s = r*pk
        let s = pk.scalar_mul(r.0).into();

        // compute c1 = r*generator
        let c1 = pp.generator.scalar_mul(r.0).into();

        // compute c2 = m + s
        let c2 = *message + s;

        Ok((c1, c2))
    }

    fn decrypt(
        _pp: &Self::Parameters,
        sk: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, Error> {
        let c1: <C as ProjectiveCurve>::Affine = ciphertext.0;
        let c2: <C as ProjectiveCurve>::Affine = ciphertext.1;

        // compute s = secret_key * c1
        let s = c1.mul(sk.0.into_repr());
        let s_inv = -s;

        // compute message = c2 - s
        let m = c2 + s_inv.into_affine();

        Ok(m)
    }
}
