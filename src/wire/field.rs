use ark_ff::Field;

use crate::share::field::FieldShare;

pub enum MpcField<F: Field, S: FieldShare<F>> {
    Public(F),
    Shared(S),
}
