use std::{
    any::Any,
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use ark_serialize::CanonicalDeserialize;

use crate::error::error::KeyError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyKind {
    ProvingKeyExt,
    PoseidonAnchorKeyExt,
    SchnorrKeyExt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyHandle(pub u64);

struct StoredKey {
    pub kind: KeyKind,
    pub data: Arc<dyn Any + Send + Sync>,
}

pub struct KeyManager {
    keys: RwLock<HashMap<KeyHandle, StoredKey>>,
    dedup: RwLock<HashMap<(PathBuf, KeyKind), KeyHandle>>,
    next_id: RwLock<u64>,
}

impl KeyManager {
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            dedup: RwLock::new(HashMap::new()),
            next_id: RwLock::new(1),
        }
    }

    fn alloc_handle(&self) -> KeyHandle {
        let mut guard = self.next_id.write().unwrap();
        let h = KeyHandle(*guard);
        *guard += 1;
        h
    }

    pub fn load_key_from_path<T>(
        &self,
        kind: KeyKind,
        path: impl Into<PathBuf>,
        loader: impl Fn(&PathBuf) -> Result<T, KeyError>,
    ) -> Result<KeyHandle, KeyError>
    where
        T: Any + Send + Sync + 'static + CanonicalDeserialize,
    {
        let path_buf = path.into();

        // dedup 확인: 동일(path, kind) 쌍이 이미 있으면 해당 handle 반환
        if let Some(h) = self.dedup.read().unwrap().get(&(path_buf.clone(), kind)) {
            return Ok(*h);
        }

        // 실제 로드
        let key_obj: T = loader(&path_buf)?;
        let handle = self.alloc_handle();

        // key / dedup 업데이트
        {
            let mut keys_w = self.keys.write().unwrap();
            keys_w.insert(
                handle,
                StoredKey {
                    kind,
                    data: Arc::new(key_obj),
                },
            );
        }
        {
            let mut dedup_w = self.dedup.write().unwrap();
            dedup_w.insert((path_buf, kind), handle);
        }

        Ok(handle)
    }

    pub fn get_kind(&self, handle: KeyHandle) -> Option<KeyKind> {
        let keys_r = self.keys.read().unwrap();
        keys_r.get(&handle).map(|stored| stored.kind)
    }

    pub fn get_typed<T>(&self, handle: KeyHandle) -> Result<Arc<T>, KeyError>
    where
        T: Any + Send + Sync + 'static,
    {
        let keys_r = self.keys.read().unwrap();
        let stored = keys_r.get(&handle).ok_or(KeyError::NotFound(handle.0))?;

        // clone arc
        let arc_any = stored.data.clone();

        // Arc<dyn Any> -> Arc<T>
        Arc::downcast::<T>(arc_any).map_err(|_| KeyError::TypeMismatch(handle.0))
    }
}
