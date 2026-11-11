//! Hashing: one read pass feeds one or two digests (never more).

use serde::{Deserialize, Serialize};
use std::io::{self, Read};

/// Size of each read. Large enough for throughput, small enough for responsive progress/cancel.
pub const CHUNK: usize = 1 << 20;

/// The algorithms a user may choose. At most two per run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HashAlgo {
    #[serde(rename = "md5")]
    Md5,
    #[serde(rename = "sha1")]
    Sha1,
    #[serde(rename = "sha256")]
    Sha256,
    #[serde(rename = "sha512")]
    Sha512,
    #[serde(rename = "sha3-256")]
    Sha3_256,
    #[serde(rename = "blake3")]
    Blake3,
}

impl HashAlgo {
    pub const ALL: [HashAlgo; 6] = [
        HashAlgo::Md5,
        HashAlgo::Sha1,
        HashAlgo::Sha256,
        HashAlgo::Sha512,
        HashAlgo::Sha3_256,
        HashAlgo::Blake3,
    ];
    pub const MAX_SELECTED: usize = 2;

    pub fn name(&self) -> &'static str {
        match self {
            HashAlgo::Md5 => "md5",
            HashAlgo::Sha1 => "sha1",
            HashAlgo::Sha256 => "sha256",
            HashAlgo::Sha512 => "sha512",
            HashAlgo::Sha3_256 => "sha3-256",
            HashAlgo::Blake3 => "blake3",
        }
    }

    pub fn parse(s: &str) -> Option<HashAlgo> {
        let s = s.trim().to_ascii_lowercase().replace('_', "-");
        HashAlgo::ALL
            .into_iter()
            .find(|a| a.name() == s || (s == "sha3" && *a == HashAlgo::Sha3_256))
    }
}

impl std::fmt::Display for HashAlgo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Rejects empty, duplicated or more-than-two selections.
pub fn validate_selection(algos: &[HashAlgo]) -> Result<(), String> {
    if algos.is_empty() {
        return Err("select at least one hash algorithm".into());
    }
    if algos.len() > HashAlgo::MAX_SELECTED {
        return Err(format!(
            "at most {} hash algorithms can run at the same time (got {})",
            HashAlgo::MAX_SELECTED,
            algos.len()
        ));
    }
    if algos.len() == 2 && algos[0] == algos[1] {
        return Err("the two hash algorithms must be different".into());
    }
    Ok(())
}

enum Hasher {
    Md5(md5::Md5),
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha512(sha2::Sha512),
    Sha3(sha3::Sha3_256),
    Blake3(Box<blake3::Hasher>),
}

impl Hasher {
    fn new(a: HashAlgo) -> Self {
        use digest::Digest;
        match a {
            HashAlgo::Md5 => Hasher::Md5(md5::Md5::new()),
            HashAlgo::Sha1 => Hasher::Sha1(sha1::Sha1::new()),
            HashAlgo::Sha256 => Hasher::Sha256(sha2::Sha256::new()),
            HashAlgo::Sha512 => Hasher::Sha512(sha2::Sha512::new()),
            HashAlgo::Sha3_256 => Hasher::Sha3(sha3::Sha3_256::new()),
            HashAlgo::Blake3 => Hasher::Blake3(Box::new(blake3::Hasher::new())),
        }
    }

    fn update(&mut self, b: &[u8]) {
        use digest::Digest;
        match self {
            Hasher::Md5(h) => h.update(b),
            Hasher::Sha1(h) => h.update(b),
            Hasher::Sha256(h) => h.update(b),
            Hasher::Sha512(h) => h.update(b),
            Hasher::Sha3(h) => h.update(b),
            Hasher::Blake3(h) => {
                h.update(b);
            }
        }
    }

    fn finalize(self) -> String {
        use digest::Digest;
        match self {
            Hasher::Md5(h) => hex(&h.finalize()),
            Hasher::Sha1(h) => hex(&h.finalize()),
            Hasher::Sha256(h) => hex(&h.finalize()),
            Hasher::Sha512(h) => hex(&h.finalize()),
            Hasher::Sha3(h) => hex(&h.finalize()),
            Hasher::Blake3(h) => h.finalize().to_hex().to_string(),
        }
    }
}

pub fn hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(D[(x >> 4) as usize] as char);
        s.push(D[(x & 15) as usize] as char);
    }
    s
}

/// Hex string to bytes (None if malformed).
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Result of hashing one stream.
pub struct HashOutcome {
    pub digests: Vec<(HashAlgo, String)>,
    pub bytes: u64,
    /// First bytes of the stream (up to 4 KiB), for signature detection without a second read.
    pub head: Vec<u8>,
}

/// Reads `r` once in CHUNK-sized blocks, feeding every selected digest.
/// `on_chunk(bytes_so_far)` is called after each block; returning `false` cancels (→ Ok(None)).
pub fn hash_reader<R: Read>(
    mut r: R,
    algos: &[HashAlgo],
    mut on_chunk: impl FnMut(u64) -> bool,
) -> io::Result<Option<HashOutcome>> {
    validate_selection(algos).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut hashers: Vec<(HashAlgo, Hasher)> = algos.iter().map(|&a| (a, Hasher::new(a))).collect();
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    let mut head = Vec::new();
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if head.len() < 4096 {
            let take = (4096 - head.len()).min(n);
            head.extend_from_slice(&buf[..take]);
        }
        for (_, h) in hashers.iter_mut() {
            h.update(&buf[..n]);
        }
        total += n as u64;
        if !on_chunk(total) {
            return Ok(None);
        }
    }
    let digests = hashers
        .into_iter()
        .map(|(a, h)| (a, h.finalize()))
        .collect();
    Ok(Some(HashOutcome {
        digests,
        bytes: total,
        head,
    }))
}

/// Convenience for tests and self-test.
pub fn hash_bytes(data: &[u8], algo: HashAlgo) -> String {
    let mut h = Hasher::new(algo);
    h.update(data);
    h.finalize()
}

/// Known-answer vectors ("abc") used by `self-test` and the unit tests.
pub const KNOWN_ANSWERS: [(HashAlgo, &str); 6] = [
    (HashAlgo::Md5, "900150983cd24fb0d6963f7d28e17f72"),
    (HashAlgo::Sha1, "a9993e364706816aba3e25717850c26c9cd0d89d"),
    (
        HashAlgo::Sha256,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ),
    (
        HashAlgo::Sha512,
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    ),
    (
        HashAlgo::Sha3_256,
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    ),
    (
        HashAlgo::Blake3,
        "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
    ),
];

/// Runs every known-answer test; returns the algorithms that failed.
pub fn self_test() -> Vec<HashAlgo> {
    KNOWN_ANSWERS
        .iter()
        .filter(|(a, want)| hash_bytes(b"abc", *a) != *want)
        .map(|(a, _)| *a)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers_pass() {
        assert!(self_test().is_empty(), "failed: {:?}", self_test());
    }

    #[test]
    fn one_pass_feeds_two_digests_identically_to_separate_passes() {
        let data: Vec<u8> = (0..3 * CHUNK + 17).map(|i| (i % 251) as u8).collect();
        let out = hash_reader(&data[..], &[HashAlgo::Sha256, HashAlgo::Blake3], |_| true)
            .unwrap()
            .unwrap();
        assert_eq!(out.bytes, data.len() as u64);
        assert_eq!(out.digests[0].1, hash_bytes(&data, HashAlgo::Sha256));
        assert_eq!(out.digests[1].1, hash_bytes(&data, HashAlgo::Blake3));
        assert_eq!(out.head.len(), 4096);
    }

    #[test]
    fn selection_rules() {
        assert!(validate_selection(&[]).is_err());
        assert!(validate_selection(&[HashAlgo::Md5, HashAlgo::Md5]).is_err());
        assert!(validate_selection(&[HashAlgo::Md5, HashAlgo::Sha1, HashAlgo::Sha256]).is_err());
        assert!(validate_selection(&[HashAlgo::Sha256, HashAlgo::Blake3]).is_ok());
        assert_eq!(HashAlgo::parse("SHA3_256"), Some(HashAlgo::Sha3_256));
        assert_eq!(HashAlgo::parse("whirlpool"), None);
    }

    #[test]
    fn cancel_stops_reading() {
        let data = vec![0u8; 4 * CHUNK];
        let r = hash_reader(&data[..], &[HashAlgo::Sha256], |n| n < 2 * CHUNK as u64).unwrap();
        assert!(r.is_none());
    }
}
