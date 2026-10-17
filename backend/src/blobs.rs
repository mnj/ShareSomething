//! Chunked file blobs on disk: `<data_dir>/blobs/<share_id>/<file_idx>.bin`.
//!
//! Each file is a sequence of encrypted chunks of a fixed stored size (the last one shorter),
//! so chunk `n` lives at offset `n * stored_chunk_size`.

use std::{
    io::SeekFrom,
    path::{Path, PathBuf},
};

use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

/// Plaintext bytes per chunk.
pub const CHUNK_SIZE: usize = 1024 * 1024;
/// Browser AES-GCM: 12-byte nonce + 16-byte tag.
pub const E2E_CHUNK_OVERHEAD: usize = 12 + 16;
/// Server XChaCha20-Poly1305: 24-byte nonce + 16-byte tag.
pub const SERVER_CHUNK_OVERHEAD: usize = crate::crypto::SEAL_OVERHEAD;

pub fn chunk_count(size: u64) -> u64 {
    size.div_ceil(CHUNK_SIZE as u64).max(1)
}

/// Plaintext length of chunk `n` of a file of `size` bytes.
pub fn plain_chunk_len(size: u64, n: u64) -> usize {
    let start = n * CHUNK_SIZE as u64;
    (size.saturating_sub(start)).min(CHUNK_SIZE as u64) as usize
}

#[derive(Clone)]
pub struct Blobs {
    root: PathBuf,
}

impl Blobs {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            root: data_dir.join("blobs"),
        }
    }

    fn share_dir(&self, share_id: &str) -> std::io::Result<PathBuf> {
        // Share ids are server-generated UUIDs; refuse anything else as a path component.
        if uuid::Uuid::parse_str(share_id).is_err() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "share id must be a uuid"));
        }
        Ok(self.root.join(share_id))
    }

    fn file_path(&self, share_id: &str, idx: u32) -> std::io::Result<PathBuf> {
        Ok(self.share_dir(share_id)?.join(format!("{idx}.bin")))
    }

    /// Writes chunk `n`, truncating anything after its start (so a retried upload is idempotent).
    pub async fn write_chunk(&self, share_id: &str, idx: u32, n: u64, stored_chunk: usize, data: &[u8]) -> std::io::Result<()> {
        tokio::fs::create_dir_all(self.share_dir(share_id)?).await?;
        let mut f = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(self.file_path(share_id, idx)?)
            .await?;
        let offset = n * stored_chunk as u64;
        f.set_len(offset).await?;
        f.seek(SeekFrom::Start(offset)).await?;
        f.write_all(data).await?;
        f.sync_data().await
    }

    pub async fn read_chunk(&self, share_id: &str, idx: u32, n: u64, stored_chunk: usize) -> std::io::Result<Vec<u8>> {
        let mut f = tokio::fs::File::open(self.file_path(share_id, idx)?).await?;
        f.seek(SeekFrom::Start(n * stored_chunk as u64)).await?;
        let mut buf = Vec::with_capacity(stored_chunk);
        f.take(stored_chunk as u64).read_to_end(&mut buf).await?;
        Ok(buf)
    }

    pub async fn file_len(&self, share_id: &str, idx: u32) -> std::io::Result<u64> {
        Ok(tokio::fs::metadata(self.file_path(share_id, idx)?).await?.len())
    }

    pub async fn remove_share(&self, share_id: &str) {
        let Ok(dir) = self.share_dir(share_id) else { return };
        match tokio::fs::remove_dir_all(dir).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::error!(share = %share_id, error = %e, "failed to remove blobs"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_math() {
        let c = CHUNK_SIZE as u64;
        assert_eq!(chunk_count(0), 1);
        assert_eq!(chunk_count(1), 1);
        assert_eq!(chunk_count(c), 1);
        assert_eq!(chunk_count(c + 1), 2);
        assert_eq!(plain_chunk_len(c + 5, 0), CHUNK_SIZE);
        assert_eq!(plain_chunk_len(c + 5, 1), 5);
        assert_eq!(plain_chunk_len(0, 0), 0);
    }

    #[tokio::test]
    async fn write_read_and_retry() {
        let dir = std::env::temp_dir().join(format!("ss-blobs-{}", uuid::Uuid::new_v4()));
        let b = Blobs::new(&dir);
        let id = uuid::Uuid::new_v4().to_string();
        b.write_chunk(&id, 0, 0, 4, b"aaaa").await.unwrap();
        b.write_chunk(&id, 0, 1, 4, b"bbbb").await.unwrap();
        b.write_chunk(&id, 0, 1, 4, b"cc").await.unwrap(); // retry replaces the chunk
        assert_eq!(b.file_len(&id, 0).await.unwrap(), 6);
        assert_eq!(b.read_chunk(&id, 0, 1, 4).await.unwrap(), b"cc");
        assert_eq!(b.read_chunk(&id, 0, 0, 4).await.unwrap(), b"aaaa");
        b.remove_share(&id).await;
        assert!(b.file_len(&id, 0).await.is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
