//! Storage Backend

use crate::GeneError;
use failure;

/// A trait describing generic array-like behaviour, without imposing any specific details on how this is actually done.
pub trait Storage {
    type Value;
    type Error: failure::Fail;

    /// Returns the number of hashes stored in the backend
    fn len(&self) -> Result<usize, Self::Error>;

    /// Store a new item and return the index of the stored item
    fn push(&mut self, item: Self::Value) -> Result<usize, Self::Error>;

    /// Return the item at the given index
    fn get(&self, index: usize) -> Result<Option<Self::Value>, Self::Error>;

    /// Return the item at the given index. Use this if you *know* that the index is valid. Requesting a hash for an
    /// invalid index may cause the a panic
    fn get_or_panic(&self, index: usize) -> Self::Value;
}

pub trait StorageExt {
    type Value;

    /// Shortens the array, keeping the first len elements and dropping the rest.
    fn truncate(&mut self, _len: usize) -> Result<(), GeneError>;

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
}

impl<T: Clone> StorageExt for Vec<T> {
    type Value = T;

    fn truncate(&mut self, len: usize) -> Result<(), GeneError> {
        self.truncate(len);
        Ok(())
    }

    fn for_each<F>(&self, f: F) -> Result<(), GeneError>
    where F: FnMut(Result<Self::Value, GeneError>) {
        self.iter().map(|v| Ok(v.clone())).for_each(f);
        Ok(())
    }
}