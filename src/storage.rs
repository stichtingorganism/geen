//! Storage Backend

use crate::GeneError;
use std::cmp::min;

/// A trait describing generic array-like behaviour, without imposing any specific details on how this is actually done.
pub trait Storage {
    type Value;
    type Error: std::error::Error;

    /// Returns the number of hashes stored in the backend
    fn len(&self) -> Result<usize, Self::Error>;

    /// Store a new item and return the index of the stored item
    fn push(&mut self, item: Self::Value) -> Result<usize, Self::Error>;

    /// Return the item at the given index
    fn get(&self, index: usize) -> Result<Option<Self::Value>, Self::Error>;

    /// Return the item at the given index. Use this if you *know* that the index is valid. Requesting a hash for an
    /// invalid index may cause the a panic
    fn get_or_panic(&self, index: usize) -> Self::Value;

    /// Remove all stored items from the the backend.
    fn clear(&mut self) -> Result<(), Self::Error>;
}

pub trait StorageExt {
    type Value;

    /// Shortens the array, keeping the first len elements and dropping the rest.
    fn truncate(&mut self, _len: usize) -> Result<(), GeneError>;

    /// Shift the array, by discarding the first n elements from the front.
    fn shift(&mut self, n: usize) -> Result<(), GeneError>;

    /// Execute the given closure for each value in the array
    fn for_each<F>(&self, f: F) -> Result<(), GeneError>
    where F: FnMut(Result<Self::Value, GeneError>);
}

impl<T: Clone> Storage for Vec<T> {
    type Error = GeneError;
    type Value = T;

    fn len(&self) -> Result<usize, Self::Error> {
        Ok(Vec::len(self))
    }

    fn push(&mut self, item: Self::Value) -> Result<usize, Self::Error> {
        Vec::push(self, item);
        Ok(self.len() - 1)
    }

    fn get(&self, index: usize) -> Result<Option<Self::Value>, Self::Error> {
        Ok((self as &[Self::Value]).get(index).map(Clone::clone))
    }

    fn get_or_panic(&self, index: usize) -> Self::Value {
        self[index].clone()
    }

    fn clear(&mut self) -> Result<(), Self::Error> {
        Vec::clear(self);
        Ok(())
    }
}

impl<T: Clone> StorageExt for Vec<T> {
    type Value = T;

    fn truncate(&mut self, len: usize) -> Result<(), GeneError> {
        self.truncate(len);
        Ok(())
    }

    fn shift(&mut self, n: usize) -> Result<(), GeneError> {
        let drain_n = min(n, self.len());
        self.drain(0..drain_n);
        Ok(())
    }

    fn for_each<F>(&self, f: F) -> Result<(), GeneError>
    where F: FnMut(Result<Self::Value, GeneError>) {
        self.iter().map(|v| Ok(v.clone())).for_each(f);
        Ok(())
    }
}