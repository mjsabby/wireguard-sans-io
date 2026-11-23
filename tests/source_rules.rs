//! Rules about the source that no test of behaviour can hold.
//!
//! Comparing a computed MAC or tag with the one a datagram carries has to
//! take the same time wherever the two differ: `crypto::ct::ct_eq`. If
//! one of these comparisons were written with `==` instead, nothing else
//! in this repository would notice — the results are the same, and for
//! sixteen bytes today's compiler even emits branch-free code for it, so
//! that `scripts/check_constant_flow.sh` sees no difference either. What
//! the next compiler makes of `==` is not ours to say. So the three
//! places are read here.
#![allow(clippy::unwrap_used, clippy::panic, clippy::string_slice)]

use std::path::Path;

/// The text of function `name` in `file`, from its `fn` line to the brace
/// that closes it.
fn body(file: &str, name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(file);
    let source = std::fs::read_to_string(&path).unwrap();
    let start = source
        .find(&format!("fn {name}"))
        .unwrap_or_else(|| panic!("{file} has no function `{name}` any more: update this test"));
    let rest = &source[start..];
    let indent = source[..start]
        .rsplit('\n')
        .next()
        .unwrap()
        .chars()
        .take_while(|c| *c == ' ')
        .count();
    let close = format!("\n{}}}\n", " ".repeat(indent));
    let end = rest.find(&close).unwrap();
    rest[..end].to_string()
}

#[test]
fn macs_and_tags_are_compared_in_constant_time() {
    for (file, name, compared) in [
        (
            "src/crypto/aead.rs",
            "tag_matches",
            "ct::ct_eq(&expected, tag)",
        ),
        ("src/cookie.rs", "verify_mac1", "ct::ct_eq(&expected, mac1)"),
        ("src/cookie.rs", "proves", "ct::ct_eq(&expected, mac2)"),
    ] {
        let text = body(file, name);
        assert!(
            text.contains(compared),
            "{file}: `{name}` no longer compares with `{compared}`:\n{text}"
        );
        // Nothing else in it compares anything: no `==`, `!=` or `.eq(`
        // (comments aside).
        for line in text.lines() {
            let code = line.split("//").next().unwrap();
            assert!(
                !code.contains("==") && !code.contains("!=") && !code.contains(".eq("),
                "{file}: `{name}` compares with an operator:\n{line}"
            );
        }
    }
}

/// The helper finds what it is asked for, and all of it.
#[test]
fn the_function_reader_reads_whole_functions() {
    let text = body("src/crypto/ct.rs", "ct_eq");
    assert!(text.starts_with("fn ct_eq(a: &[u8], b: &[u8]) -> bool {"));
    assert!(
        text.trim_end()
            .ends_with("core::hint::black_box(diff) == 0")
    );
}
