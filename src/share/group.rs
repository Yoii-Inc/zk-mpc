use ark_ec::{group::Group, AffineCurve};

pub trait GroupShare<G: Group> {}

pub trait GroupAffineShare<G: AffineCurve> {}
