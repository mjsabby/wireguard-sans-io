//! OS entropy → [`EntropySource`].

use wireguard_sans_io::{EntropyError, EntropySource};

/// [`EntropySource`] backed by the operating system's CSPRNG via
/// `getrandom` (RtlGenRandom / getrandom(2) / SecRandomCopyBytes / …).
///
/// This is the only place `wireguard-embed` reaches outside std.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::getrandom(buf).map_err(|_| EntropyError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fills_nonzero() {
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        #[allow(clippy::unwrap_used)]
        {
            OsEntropy.fill(&mut a).unwrap();
            OsEntropy.fill(&mut b).unwrap();
        }
        assert_ne!(a, [0u8; 64]);
        assert_ne!(a, b, "two draws should differ");
    }
}
