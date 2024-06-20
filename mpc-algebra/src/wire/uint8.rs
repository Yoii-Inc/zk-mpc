use crate::{boolean_field::MpcBooleanField, FieldShare};
use ark_ff::Field;

#[derive(Clone, Copy, Debug, Hash)]
pub struct MpcU8Field<F: Field, S: FieldShare<F>>([MpcBooleanField<F, S>; 8]);

impl<F: Field, S: FieldShare<F>> From<u8> for MpcU8Field<F, S> {
    fn from(value: u8) -> Self {
        let mut bits = [MpcBooleanField::from(false); 8];
        for i in 0..8 {
            bits[i] = MpcBooleanField::from((value >> i) & 1 == 1);
        }
        MpcU8Field(bits)
    }
}

impl<F: Field, S: FieldShare<F>> From<[MpcBooleanField<F, S>; 8]> for MpcU8Field<F, S> {
    fn from(value: [MpcBooleanField<F, S>; 8]) -> Self {
        MpcU8Field(value)
    }
}

impl<F: Field, S: FieldShare<F>> MpcU8Field<F, S> {
    pub fn get(&self) -> [MpcBooleanField<F, S>; 8] {
        self.0
    }
}
