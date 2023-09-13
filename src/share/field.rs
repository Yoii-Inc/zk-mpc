use ark_ff::Field;

pub trait FieldShare {}

pub trait ExtFieldShare<F: Field> {
    type Ext: FieldShare<F>;
}
