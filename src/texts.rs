use num_traits::Zero;
use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Texts<T: Clone> {
    pub vals: Vec<T>,
}

impl<T: Clone> Texts<T> {
    pub fn new() -> Self {
        Texts { vals: Vec::new() }
    }

    pub fn from(vals: &[T]) -> Self {
        Texts {
            vals: vals.to_vec(),
        }
    }

    pub fn from_vec(vals: Vec<T>) -> Self {
        Texts { vals }
    }

    pub fn push(&mut self, val: T) {
        self.vals.push(val);
    }

    pub fn get(&self, index: usize) -> &T {
        &self.vals[index]
    }

    pub fn len(&self) -> usize {
        self.vals.len()
    }
}

// impl Add
impl<T: Clone + Zero> Add for Texts<T> {
    type Output = Self;

    /// lenght should be same
    fn add(self, other: Self) -> Self {
        assert!(self.len() == other.len());
        let mut res = vec![T::zero(); self.vals.len()];
        #[allow(clippy::needless_range_loop)]
        for i in 0..self.vals.len() {
            res[i] = self.vals[i].clone() + other.vals[i].clone();
        }
        Texts { vals: res }
    }
}

impl<T: Clone + AddAssign> AddAssign for Texts<T> {
    fn add_assign(&mut self, other: Self) {
        assert!(self.len() == other.len());
        #[allow(clippy::needless_range_loop)]
        for i in 0..self.vals.len() {
            self.vals[i] += other.vals[i].clone();
        }
    }
}

impl<T: Clone + Zero + AddAssign> std::iter::Sum for Texts<T> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut iter = iter.peekable();

        // Get the maximum length from the iterator or use 0 if empty
        let max_length = iter.peek().map(|x| x.len()).unwrap_or(0);

        // Initialize with default value
        let mut res = Texts::from_vec(vec![T::zero(); max_length]);

        for i in iter {
            res += i;
        }

        res
    }
}

impl<T: Clone + Neg<Output = T> + Sized> Neg for Texts<T> {
    type Output = Self;

    fn neg(self) -> Self {
        Texts {
            vals: self.vals.iter().map(|x| -x.clone()).collect::<Vec<T>>(),
        }
    }
}

impl<T: Clone + Zero + SubAssign> SubAssign for Texts<T> {
    fn sub_assign(&mut self, other: Self) {
        assert!(self.len() == other.len());
        #[allow(clippy::needless_range_loop)]
        for i in 0..self.vals.len() {
            self.vals[i] -= other.vals[i].clone();
        }
    }
}

// impl Mul
impl<T: Clone + Zero + Mul<T, Output = T>> Mul for Texts<T> {
    type Output = Self;

    /// lenght should be same
    fn mul(self, other: Self) -> Self {
        assert!(self.len() == other.len());
        let mut res = vec![T::zero(); self.vals.len()];
        #[allow(clippy::needless_range_loop)]
        for i in 0..self.vals.len() {
            res[i] = self.vals[i].clone() * other.vals[i].clone();
        }
        Texts { vals: res }
    }
}

impl<T: Clone + Zero + Sub<Output = T>> Sub for Texts<T> {
    type Output = Self;

    /// lenght should be same
    fn sub(self, other: Self) -> Self {
        assert!(self.len() == other.len());
        let mut res = vec![T::zero(); self.vals.len()];
        #[allow(clippy::needless_range_loop)]
        for i in 0..self.vals.len() {
            res[i] = self.vals[i].clone() - other.vals[i].clone();
        }
        Texts { vals: res }
    }
}

#[cfg(test)]
mod test {
    use crate::texts::Texts;
    #[test]
    fn test_texts_clone() {
        let a: Texts<i32> = Texts::from(&[1, 2, 3]);
        let b = a.clone();
        assert_eq!(a, b);
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn test_texts_add() {
        let a = Texts::from(&[1, 2, 3]);
        let b = Texts::from(&[4, 5, 6]);
        let c = a + b;
        assert_eq!(c, Texts::from(&[5, 7, 9]));
    }

    #[test]
    fn test_texts_add_assign() {
        let mut a = Texts::from(&[1, 2, 3]);
        let b = Texts::from(&[4, 5, 6]);
        a += b.clone();
        assert_eq!(a, Texts::from(&[5, 7, 9]));
    }

    #[test]
    fn test_texts_sum() {
        let a = Texts::from(&[1, 2, 3]);
        let b = Texts::from(&[4, 5, 6]);
        let c = Texts::from(&[7, 8, 9]);
        let d1 = a.clone() + b.clone() + c.clone();
        let d2 = vec![a.clone(), b.clone(), c.clone()]
            .into_iter()
            .sum::<Texts<i32>>();
        assert_eq!(d1, Texts::from(&[12, 15, 18]));
        assert_eq!(d2, Texts::from(&[12, 15, 18]));
    }

    #[test]
    fn test_texts_neg() {
        let a = Texts::from(&[1, 2, 3]);
        let b = -a;
        assert_eq!(b, Texts::from(&[-1, -2, -3]));
    }

    #[test]
    fn test_texts_sub() {
        let a = Texts::from(&[1, 2, 3]);
        let b = Texts::from(&[4, 5, 6]);
        let c = a - b;
        assert_eq!(c, Texts::from(&[-3, -3, -3]));
    }

    #[test]
    fn test_texts_sub_assign() {
        let mut a = Texts::from(&[1, 2, 3]);
        let b = Texts::from(&[4, 5, 6]);
        a -= b;
        assert_eq!(a, Texts::from(&[-3, -3, -3]));
    }

    #[test]
    fn test_texts_mul() {
        let a = Texts::from(&[1, 2, 3]);
        let b = Texts::from(&[4, 5, 6]);
        let c = a * b;
        assert_eq!(c, Texts::from(&[4, 10, 18]));
    }
}
