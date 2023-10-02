pub trait Reveal {
    type Base;

    fn reveal(&self) -> Self::Base;
}
