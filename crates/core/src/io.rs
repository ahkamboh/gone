//! Evidence sources: raw/dd images, E01, AFF4, sparsebundle, live devices.
//!
//! Everything above this layer sees a single `Read + Seek` abstraction.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

/// A byte range inside an evidence source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub offset: u64,
    pub len: u64,
}

/// `Read + Seek` as a single object-safe trait.
pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

/// A read-only evidence source: a raw image, a device, or any seekable
/// byte stream wrapped by a format adapter (E01, AFF4, sparsebundle).
pub struct EvidenceSource {
    inner: Box<dyn ReadSeek>,
    size: u64,
    name: String,
}

impl EvidenceSource {
    /// Open a file read-only (raw image today, more formats via adapters).
    pub fn open(path: &Path) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let size = file.seek(SeekFrom::End(0))?;
        file.seek(SeekFrom::Start(0))?;
        Ok(Self {
            inner: Box::new(file),
            size,
            name: path.display().to_string(),
        })
    }

    /// Wrap any seekable reader. Used by tests and by format adapters.
    pub fn from_reader(
        name: impl Into<String>,
        mut reader: impl ReadSeek + 'static,
    ) -> io::Result<Self> {
        let size = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;
        Ok(Self {
            inner: Box::new(reader),
            size,
            name: name.into(),
        })
    }

    /// Total size in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Display name of the source (path or adapter description).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Read up to `buf.len()` bytes starting at absolute `offset`.
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.seek(SeekFrom::Start(offset))?;
        self.inner.read(buf)
    }

    /// Iterate consecutive regions of `block` bytes. The last region may
    /// be shorter.
    pub fn regions(&self, block: u64) -> RegionIter {
        RegionIter {
            next: 0,
            end: self.size,
            block,
        }
    }
}

/// Iterator over consecutive [`Region`]s of an evidence source.
pub struct RegionIter {
    next: u64,
    end: u64,
    block: u64,
}

impl Iterator for RegionIter {
    type Item = Region;

    fn next(&mut self) -> Option<Region> {
        if self.next >= self.end {
            return None;
        }
        let len = (self.end - self.next).min(self.block);
        let region = Region {
            offset: self.next,
            len,
        };
        self.next += len;
        Some(region)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn source(bytes: Vec<u8>) -> EvidenceSource {
        EvidenceSource::from_reader("test", Cursor::new(bytes)).unwrap()
    }

    #[test]
    fn size_and_name() {
        let src = source(vec![0u8; 100]);
        assert_eq!(src.size(), 100);
        assert_eq!(src.name(), "test");
    }

    #[test]
    fn read_at_offsets() {
        let data: Vec<u8> = (0..=255).collect();
        let mut src = source(data);
        let mut buf = [0u8; 4];
        assert_eq!(src.read_at(10, &mut buf).unwrap(), 4);
        assert_eq!(buf, [10, 11, 12, 13]);
        assert_eq!(src.read_at(253, &mut buf).unwrap(), 3);
    }

    #[test]
    fn regions_cover_source_exactly() {
        let src = source(vec![0u8; 2500]);
        let regions: Vec<Region> = src.regions(1000).collect();
        assert_eq!(regions.len(), 3);
        assert_eq!(
            regions[0],
            Region {
                offset: 0,
                len: 1000
            }
        );
        assert_eq!(
            regions[1],
            Region {
                offset: 1000,
                len: 1000
            }
        );
        assert_eq!(
            regions[2],
            Region {
                offset: 2000,
                len: 500
            }
        );
    }

    #[test]
    fn empty_source_has_no_regions() {
        let src = source(Vec::new());
        assert_eq!(src.regions(1000).count(), 0);
    }
}
