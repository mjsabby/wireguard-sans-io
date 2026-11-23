#!/usr/bin/env python3
"""The public API of the core crate, and the probe's list of it.

`probes/freestanding` is searched for panic machinery by
`scripts/check_no_panic.sh`. A panic can only be found in code that is in
the image, compiled for arguments the optimiser knows nothing about. So
the image takes the *address* of every public function, method and
trait-implementation method of the crate: each then has to exist as a
function of its own that works for any arguments at all.

That list is generated here, from rustdoc's JSON description of the
crate, so that nothing public can be missing from it:

    probe_api.py list <rustdoc.json>    the public API, one item per line
    probe_api.py keep <api.txt>         probes/freestanding/src/keep.rs

Both outputs are checked in (`probes/freestanding/api.txt`, `src/keep.rs`),
and `check_no_panic.sh` regenerates and compares them where a nightly
toolchain is at hand (rustdoc's JSON output is unstable). A function that
is added without the list being regenerated fails that check; a generic
function that is added has to be given the types it is to be compiled for
(`INSTANCES` below), or generating fails.
"""
import json
import re
import sys

ROOT = "wireguard_sans_io"

# ---------------------------------------------------------------------------
# list: rustdoc JSON -> one line per public item
# ---------------------------------------------------------------------------


def type_name(t):
    """A type as rustdoc describes it, written out."""
    if t is None:
        return "()"
    if "resolved_path" in t:
        path = t["resolved_path"]
        name = path.get("path") or path.get("name")
        args = path.get("args")
        if args and "angle_bracketed" in args:
            inner = []
            for arg in args["angle_bracketed"]["args"]:
                if "type" in arg:
                    inner.append(type_name(arg["type"]))
                elif "lifetime" in arg:
                    inner.append(arg["lifetime"])
                elif "const" in arg:
                    inner.append(str(arg["const"].get("expr")))
            if inner:
                name += "<" + ",".join(inner) + ">"
        return name
    if "generic" in t:
        return t["generic"]
    if "primitive" in t:
        return t["primitive"]
    if "borrowed_ref" in t:
        ref = t["borrowed_ref"]
        return "&" + ("mut " if ref.get("is_mutable") else "") + type_name(ref["type"])
    if "slice" in t:
        return "[" + type_name(t["slice"]) + "]"
    if "array" in t:
        return "[" + type_name(t["array"]["type"]) + ";" + str(t["array"]["len"]) + "]"
    if "tuple" in t:
        return "(" + ",".join(type_name(x) for x in t["tuple"]) + ")"
    if "dyn_trait" in t:
        traits = t["dyn_trait"]["traits"]
        return "dyn " + "+".join(type_name({"resolved_path": x["trait"]}) for x in traits)
    if "impl_trait" in t:
        return "impl ..."
    if "qualified_path" in t:
        q = t["qualified_path"]
        return "<" + type_name(q["self_type"]) + ">::" + q["name"]
    raise SystemExit("probe_api.py: a kind of type this script does not know: " + json.dumps(t)[:120])


def signature(item):
    """`fn name<T,N>(a: A, b: B) -> R`, with the type and const parameters
    (not the lifetimes: they need no instance)."""
    function = item["inner"]["function"]
    sig = function["sig"]
    inputs = ", ".join(f"{name}: {type_name(ty)}" for name, ty in sig["inputs"])
    output = type_name(sig.get("output")) if sig.get("output") else "()"
    params = [
        p["name"]
        for p in function.get("generics", {}).get("params", [])
        if "lifetime" not in p.get("kind", {})
    ]
    generics = "<" + ",".join(params) + ">" if params else ""
    const = "const " if function.get("header", {}).get("is_const") else ""
    return f"{const}fn {item['name']}{generics}({inputs}) -> {output}"


def list_api(path):
    doc = json.load(open(path))
    index = doc["index"]
    out = set()
    seen = set()

    def visit(item_id, module):
        key = (item_id, tuple(module))
        if key in seen:
            return
        seen.add(key)
        item = index.get(str(item_id))
        if item is None:
            return
        inner = item["inner"]
        kind = next(iter(inner))
        name = item.get("name")
        public = item.get("visibility") == "public"
        where = "::".join(module)
        if kind == "module":
            for child in inner["module"]["items"]:
                visit(child, module + [name])
        elif kind == "use":
            use = inner["use"]
            if use.get("id") is not None and public:
                target = index.get(str(use["id"]))
                if target is not None:
                    if use.get("is_glob") and "module" in target["inner"]:
                        for child in target["inner"]["module"]["items"]:
                            visit(child, module)
                    else:
                        visit(use["id"], module)
        elif kind == "function":
            if public:
                out.add(("fn", where, signature(item)))
        elif kind in ("struct", "enum", "union"):
            if not public:
                return
            out.add((kind, where, name))
            for impl_id in inner[kind].get("impls", []):
                impl_item = index.get(str(impl_id))
                if impl_item is None:
                    continue
                impl = impl_item["inner"]["impl"]
                # Auto traits and blanket impls are not this crate's code.
                if impl.get("is_synthetic") or impl.get("blanket_impl") is not None:
                    continue
                for_type = type_name(impl["for"])
                params = [
                    p["name"]
                    for p in impl.get("generics", {}).get("params", [])
                    if "lifetime" not in p.get("kind", {})
                ]
                generics = "<" + ",".join(params) + "> " if params else ""
                if impl.get("trait") is None:
                    for member_id in impl["items"]:
                        member = index.get(str(member_id))
                        if member is None or member.get("visibility") != "public":
                            continue
                        if "function" in member["inner"]:
                            out.add(("method", where, f"impl {generics}{for_type} :: {signature(member)}"))
                else:
                    trait = type_name({"resolved_path": impl["trait"]})
                    methods = []
                    for member_id in impl["items"]:
                        member = index.get(str(member_id))
                        if member is not None and "function" in member["inner"]:
                            methods.append(member["name"])
                    provided = sorted(impl.get("provided_trait_methods", []))
                    out.add((
                        "trait_impl",
                        where,
                        f"impl {generics}{trait} for {for_type} {{{','.join(methods)}}}"
                        f" provided {{{','.join(provided)}}}",
                    ))
        elif kind == "trait":
            if public:
                out.add((kind, where, name))
        elif public and name:
            out.add((kind, where, name))

    root = index[str(doc["root"])]
    for child in root["inner"]["module"]["items"]:
        visit(child, [root["name"]])
    for kind, where, text in sorted(out):
        print(f"{kind}\t{where}\t{text}")


# ---------------------------------------------------------------------------
# keep: the listing -> keep.rs
# ---------------------------------------------------------------------------

# What each generic function is compiled for: every instance the crate
# itself uses, and for the provider parameters the probe's own (`P`, `C`).
INSTANCES = {
    "crypto::aead::open_in_place_with": ["::<C>"],
    "crypto::aead::open_with": ["::<C>"],
    "crypto::aead::seal_in_place_with": ["::<C>"],
    "crypto::aead::seal_with": ["::<C>"],
    "crypto::ct::copy_secret": ["::<32>", "::<16>"],
    "crypto::ct::swap_secret": ["::<32>", "::<16>"],
    "crypto::ct::wipe_array": ["::<32>", "::<16>", "::<64>"],
    "crypto::ct::wipe_words": ["::<u64, 5>", "::<u32, 16>", "::<u32, 8>", "::<u64, 4>"],
    "crypto::kdf::kdf_chain": ["::<P, 0>", "::<P, 1>", "::<P, 2>"],
    "crypto::kdf::kdf_into": ["::<P, 0>", "::<P, 1>", "::<P, 2>", "::<P, 3>"],
}
METHOD_INSTANCES = {
    "public_key_with": "::<P>",
}

# Traits this crate implements for its public types, by the name rustdoc
# gives them. `None`: nothing to take the address of (marker traits), or
# handled specially (`Drop`).
TRAITS = {
    "Clone": "core::clone::Clone",
    "Copy": None,
    "Debug": "core::fmt::Debug",
    "Display": "core::fmt::Display",
    "Default": "core::default::Default",
    "PartialEq": "core::cmp::PartialEq",
    "Eq": None,
    "StructuralPartialEq": None,
    "PartialOrd": "core::cmp::PartialOrd",
    "Ord": "core::cmp::Ord",
    "Hash": "core::hash::Hash",
    "Error": None,
    "From<[u8;32]>": "core::convert::From<[u8; 32]>",
    "CryptoProvider": "wg::CryptoProvider",
    "ChaChaImpl": "wg::ChaChaImpl",
    "EntropySource": "wg::EntropySource",
    "Drop": "drop",
}
# Methods a trait provides on top of the ones a type implements: they are
# compiled for the type too.
PROVIDED = {
    "PartialEq": ["ne"],
    "Clone": ["clone_from"],
    "PartialOrd": ["lt", "le", "gt", "ge"],
    "Ord": ["max", "min"],
}
# Methods of this crate's own traits that are generic themselves, and the
# instance to take — whether a type takes the one the trait provides or
# has its own.
PROVIDED_INSTANCES = {
    "open_keystream": "::<fn(&[u8; 32], &[u8]) -> bool>",
}


def keep(path):
    lines = [line.rstrip("\n").split("\t") for line in open(path) if line.strip()]
    # The public path of each type: the re-export at the crate root if
    # there is one.
    module_of = {}
    for kind, where, text in lines:
        if kind in ("struct", "enum") and (text not in module_of or where == ROOT):
            module_of[text] = where

    def public(name):
        return "wg" + module_of[name][len(ROOT):] + "::" + name

    def split_type(ty):
        """`Device<P>` -> (`Device`, `<P>`)."""
        head = re.match(r"[\w:]+", ty).group(0)
        return head.split("::")[-1], ty[len(head):]

    groups = {"api": [], "traits": [], "fmt": []}
    seen = set()

    def emit(group, expression):
        if expression not in seen:
            seen.add(expression)
            groups[group].append(f"    k!({expression});")

    for kind, where, text in lines:
        if kind == "fn":
            match = re.match(r"(?:const )?fn (\w+)(<[^>(]*>)?\(", text)
            name, generics = match.group(1), match.group(2)
            relative = (where[len(ROOT):] + "::" + name).lstrip(":")
            if generics:
                if relative not in INSTANCES:
                    raise SystemExit(
                        f"probe_api.py: {relative}{generics} is generic and has no entry in "
                        "INSTANCES: say what it is to be compiled for"
                    )
                instances = INSTANCES[relative]
            else:
                instances = [""]
            for instance in instances:
                emit("api", f"wg::{relative}{instance}")
        elif kind == "method":
            match = re.match(r"impl (<[^>]*> )?(.+?) :: (?:const )?fn (\w+)(<[^>(]*>)?\(", text)
            _, ty, name, generics = match.groups()
            base, args = split_type(ty)
            if args in ("<P>", "<C>"):
                target = public(base) + "::" + args
            elif args == "<crate::crypto::InTree>":
                target = public(base) + "::<wg::InTree>"
            elif args == "" or re.fullmatch(r"<'\w+>", args):
                # (A lifetime needs no instance: the path leaves it out.)
                target = public(base)
            else:
                raise SystemExit("probe_api.py: type arguments this script does not know: " + text)
            instance = ""
            if generics:
                if name not in METHOD_INSTANCES:
                    raise SystemExit(
                        f"probe_api.py: method {name}{generics} is generic and has no entry in "
                        "METHOD_INSTANCES"
                    )
                instance = METHOD_INSTANCES[name]
            emit("api", f"{target}::{name}{instance}")
        elif kind == "trait_impl":
            match = re.match(
                r"impl (<[^>]*> )?(.+?) for (.+?) \{([^}]*)\} provided \{([^}]*)\}", text
            )
            _, trait, ty, methods, provided = match.groups()
            methods = [m for m in methods.split(",") if m]
            provided = [m for m in provided.split(",") if m]
            base, args = split_type(ty)
            if re.fullmatch(r"<'\w+>", args):
                target = public(base) + "<'static>"
            elif args in ("<P>", "<C>", ""):
                target = public(base) + args
            else:
                raise SystemExit("probe_api.py: type arguments this script does not know: " + text)
            if trait not in TRAITS:
                raise SystemExit("probe_api.py: a trait this script does not know: " + text)
            path = TRAITS[trait]
            if path is None:
                continue
            if path == "drop":
                emit("traits", f"core::ptr::drop_in_place::<{target}>")
                continue
            group = "fmt" if trait in ("Debug", "Display") else "traits"
            local = path.startswith("wg::")
            if local:
                group = "api"
            for method in methods:
                instance = "::<H>" if (trait, method) == ("Hash", "hash") else ""
                if local:
                    instance = PROVIDED_INSTANCES.get(method, "")
                emit(group, f"<{target} as {path}>::{method}{instance}")
            for method in PROVIDED.get(trait, []):
                emit(group, f"<{target} as {path}>::{method}")
            if local:
                # What the trait provides and the type does not override
                # is compiled for the type as well.
                for method in provided:
                    emit("api", f"<{target} as {path}>::{method}{PROVIDED_INSTANCES.get(method, '')}")

    print("// @generated by scripts/probe_api.py from rustdoc's description of the core crate.")
    print("// Do not edit: `UPDATE=1 scripts/check_no_panic.sh` writes it.")
    print("//")
    print("// The address of every public function, method and trait-implementation")
    print("// method: each has to be in the image as a function of its own, compiled")
    print("// for any arguments.")
    print("#![allow(clippy::all, clippy::pedantic)]")
    print("use wireguard_sans_io as wg;")
    total = 0
    for group in ("api", "traits", "fmt"):
        print()
        print(f"/// {len(groups[group])} addresses.")
        print(
            f"pub fn keep_{group}<P: wg::CryptoProvider, C: wg::ChaChaImpl, H: core::hash::Hasher>() {{"
        )
        print("    macro_rules! k {")
        print("        ($e:expr) => {")
        print("            core::hint::black_box($e as *const ());")
        print("        };")
        print("    }")
        print("\n".join(groups[group]))
        print("}")
        total += len(groups[group])
    print(f"probe_api.py: {total} addresses", file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "list":
        list_api(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == "keep":
        keep(sys.argv[2])
    else:
        raise SystemExit(__doc__)
