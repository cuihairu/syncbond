use syncbond_core::storage::SyncStorage;
use std::path::PathBuf;

struct Mem;
impl SyncStorage for Mem {
    fn save(&self, _s: &[u8]) -> Result<(), syncbond_core::storage::StorageError> { Ok(()) }
    fn load(&self) -> Result<Option<Vec<u8>>, syncbond_core::storage::StorageError> { Ok(None) }
}

#[test]
fn storage_impl_smoke() {
    let m = Mem;
    assert!(m.save(b"x").is_ok());
    assert!(m.load().unwrap().is_none());
    let p = PathBuf::from("/tmp/syncbond-storage-x.json");
    let _ = std::fs::remove_file(&p);
    assert!(m.load().is_ok());
}
