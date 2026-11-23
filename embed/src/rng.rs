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

/// What a [`crate::Tunn`] draws from: [`OsEntropy`] — which this crate's
/// own tests can switch off, to see what the driver does when the
/// operating system has none to give.
#[derive(Debug, Default)]
pub(crate) struct TunnEntropy {
    #[cfg(test)]
    broken: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl EntropySource for TunnEntropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), EntropyError> {
        #[cfg(test)]
        if self.broken.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(EntropyError);
        }
        OsEntropy.fill(buf)
    }
}

#[cfg(all(test, feature = "async"))]
impl TunnEntropy {
    /// While this is `true`, every draw fails.
    pub(crate) fn switch(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::clone(&self.broken)
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
