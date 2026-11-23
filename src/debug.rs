//! `Debug` output that cannot panic.
//!
//! Printing is not what this library is for, but what it prints is part
//! of what it promises: `scripts/check_no_panic.sh` prints every public
//! type and then looks for panic machinery in the image. Two things in
//! libcore's formatting put some there, although neither can fire:
//!
//! * `core::net`'s `Display` for addresses formats into a buffer on the
//!   stack first, with a panic for the buffer being too small. [`Addr`]
//!   writes straight to the formatter instead.
//! * What `#[derive(Debug)]` generates for a struct with more than five
//!   fields goes through a helper that checks, when it runs, that it was
//!   given as many names as values. [`debug_struct!`] generates the plain
//!   chain of `.field()` calls.

use core::fmt;
use core::net::SocketAddr;

/// `Debug` for a struct, field by field: `debug_struct!(Name { a, b })`,
/// or `debug_struct!(Name<'a> { a, b })`. Every field has to be named —
/// one that is added later and not listed here does not compile.
macro_rules! debug_struct {
    ($name:ident $(<$lifetime:lifetime>)? { $($field:ident),+ $(,)? }) => {
        impl $(<$lifetime>)? core::fmt::Debug for $name $(<$lifetime>)? {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let Self { $($field),+ } = self;
                f.debug_struct(stringify!($name))
                    $(.field(stringify!($field), $field))+
                    .finish()
            }
        }
    };
}
pub(crate) use debug_struct;

/// A socket address, for the `Debug` output of the types that hold one:
/// `192.0.2.1:51820`, `[2001:db8:0:0:0:0:0:1]:51820`. (IPv6 addresses in
/// full, without `::`, and without a scope: this is for logs, not for
/// parsing.)
pub(crate) struct Addr(pub SocketAddr);

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            SocketAddr::V4(v4) => {
                let [a, b, c, d] = v4.ip().octets();
                write!(f, "{a}.{b}.{c}.{d}:{}", v4.port())
            }
            SocketAddr::V6(v6) => {
                let [a, b, c, d, e, g, h, i] = v6.ip().segments();
                write!(
                    f,
                    "[{a:x}:{b:x}:{c:x}:{d:x}:{e:x}:{g:x}:{h:x}:{i:x}]:{}",
                    v6.port()
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::format;

    #[test]
    fn addresses_print_as_addresses() {
        let v4: SocketAddr = "192.0.2.1:51820".parse().unwrap();
        // For IPv4 this is what the standard library prints.
        assert_eq!(format!("{:?}", Addr(v4)), format!("{v4}"));
        assert_eq!(format!("{:?}", Addr(v4)), "192.0.2.1:51820");
        let zero: SocketAddr = "0.0.0.0:0".parse().unwrap();
        assert_eq!(format!("{:?}", Addr(zero)), "0.0.0.0:0");
        let v6: SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
        assert_eq!(format!("{:?}", Addr(v6)), "[2001:db8:0:0:0:0:0:1]:51820");
        let mapped: SocketAddr = "[::ffff:192.0.2.1]:9".parse().unwrap();
        assert_eq!(format!("{:?}", Addr(mapped)), "[0:0:0:0:0:ffff:c000:201]:9");
        let all: SocketAddr = "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"
            .parse()
            .unwrap();
        assert_eq!(format!("{:?}", Addr(all)), format!("{all}"));
        // In an `Option`, as the types that hold one print it.
        assert_eq!(format!("{:?}", Some(Addr(v4))), "Some(192.0.2.1:51820)");
        assert_eq!(format!("{:?}", None::<Addr>), "None");
    }

    /// The macro prints what the derive prints.
    #[test]
    fn a_struct_prints_as_the_derive_would_print_it() {
        struct Ours<'a> {
            number: u32,
            bytes: &'a [u8; 2],
            maybe: Option<u8>,
        }
        debug_struct!(Ours<'a> { number, bytes, maybe });
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Derived<'a> {
            number: u32,
            bytes: &'a [u8; 2],
            maybe: Option<u8>,
        }
        let ours = Ours {
            number: 7,
            bytes: &[1, 2],
            maybe: None,
        };
        let derived = Derived {
            number: 7,
            bytes: &[1, 2],
            maybe: None,
        };
        assert_eq!(
            format!("{ours:?}").replace("Ours", "Derived"),
            format!("{derived:?}")
        );
        assert_eq!(
            format!("{ours:#?}").replace("Ours", "Derived"),
            format!("{derived:#?}")
        );
    }
}
