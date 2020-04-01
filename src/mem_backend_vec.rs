
use std::sync::{
    Arc,
    RwLock
};
use crate::{
    GeneError,
    Storage,
    StorageExt
};
use std::cmp::min;

/// MemBackendVec is a shareable, memory only, vector that can be be used with MmrCache to store checkpoints.
#[derive(Debug, Clone, Default)]
pub struct MemBackendVec<T> {
    db: Arc<RwLock<Vec<T>>>,
}

impl<T> MemBackendVec<T> {
    pub fn new() -> Self {
        Self {
            db: Arc::new(RwLock::new(Vec::<T>::new())),
        }
    }
}

impl<T: Clone> Storage for MemBackendVec<T> {
    type Error = GeneError;
    type Value = T;

    fn len(&self) -> Result<usize, Self::Error> {
        Ok(self
            .db
            .read()
            .map_err(|e| GeneError::BackendError(e.to_string()))?
            .len())
    }

    fn is_empty(&self) -> Result<bool, Self::Error> {
        Ok(self
            .db
            .read()
            .map_err(|e| GeneError::BackendError(e.to_string()))?
            .is_empty())
    }

    fn push(&mut self, item: Self::Value) -> Result<usize, Self::Error> {
        self.db
            .write()
            .map_err(|e| GeneError::BackendError(e.to_string()))?
            .push(item);
        Ok(self.len()? - 1)
    }

    fn get(&self, index: usize) -> Result<Option<Self::Value>, Self::Error> {
        Ok(self
            .db
            .read()
            .map_err(|e| GeneError::BackendError(e.to_string()))?
            .get(index)
            .map_err(|e| GeneError::BackendError(e.to_string()))?)
    }

    fn get_or_panic(&self, index: usize) -> Self::Value {
        self.db.read().unwrap()[index].clone()
    }

    fn clear(&mut self) -> Result<(), Self::Error> {
        self.db
            .write()
            .map_err(|e| GeneError::BackendError(e.to_string()))?
            .clear();
        Ok(())
    }
}

impl<T: Clone> StorageExt for MemBackendVec<T> {
    type Value = T;

    fn truncate(&mut self, len: usize) -> Result<(), GeneError> {
        self.db
            .write()
            .map_err(|e| GeneError::BackendError(e.to_string()))?
            .truncate(len);
        Ok(())
    }

    fn shift(&mut self, n: usize) -> Result<(), GeneError> {
        let drain_n = min(
            n,
            self.len()
                .map_err(|e| GeneError::BackendError(e.to_string()))?,
        );
        self.db
            .write()
            .map_err(|e| GeneError::BackendError(e.to_string()))?
            .drain(0..drain_n);
        Ok(())
    }

    fn for_each<F>(&self, f: F) -> Result<(), GeneError>
    where F: FnMut(Result<Self::Value, GeneError>) {
        self.db
            .read()
            .map_err(|e| GeneError::BackendError(e.to_string()))?
            .iter()
            .map(|v| Ok(v.clone()))
            .for_each(f);
        Ok(())
    }
}