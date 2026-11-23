#!/usr/bin/env python3
"""Is every wipe there for something the residue check can see?

`scripts/check_secret_residue.sh` says that no secret is left behind. That
is worth as much as its ability to notice when one is. This script takes
the wipes away one at a time and looks:

  * every statement that zeroes key material or overwrites a stack frame
    — `ct::wipe…(…)`, `….wipe()`, `ct::scrub_stack_to(…)`,
    `ct::scrub_frame::<…>(…)`, the frame guards (`ScrubOnDrop`), the
    clean-up after the SIMD kernels — is found in the library crates;
  * in a copy of the repository, one of them is removed, the three
    residue probes are built and run (release build, then the dev
    profile, then unoptimised), and the copy is restored;
  * the probes have to fail. If they do not, the removal has *survived*.

A survivor is one of two things: a blind spot of the probes, or a wipe
nothing depends on. Both are worth knowing about, and neither should
appear unnoticed. The survivors that are known and understood are listed
in `EXPECTED` below, each with its reason — they are second lines of
defence (a buffer zeroed inside a frame that is overwritten as a whole
afterwards, a slot wiped again before it is filled) or sit on error
paths no test can take (the cipher failing to seal sixteen bytes into
thirty-two). Anything else that survives fails this script; so does an
entry of the list that the probes have since learned to catch, so that
the list stays true.

    scripts/check_wipes_matter.py [--jobs N] [--only TEXT] [--list]

`--list` prints the statements and exits; `--only` takes those whose
description contains TEXT. A full run builds the probes several hundred
times: about an hour with five jobs on a large machine. It needs what
`check_secret_residue.sh` needs, and `rsync`.
"""

import argparse
import concurrent.futures
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent

# The library crates' sources (the NEON backend cannot run here: its
# clean-up is checked by the residue script itself, under emulation).
FILES = sorted((ROOT / "src").rglob("*.rs")) + [
    ROOT / "simd/src/lib.rs",
    ROOT / "simd/src/avx2.rs",
    ROOT / "simd/src/avx512.rs",
    ROOT / "embed/src/lib.rs",
]
SKIP_FILES = {"testing.rs"}

STATEMENT = re.compile(
    r"""^\s*(
      ct::wipe(_array|_words)?\(.*\);
    | (crate::crypto::|wireguard_sans_io::crypto::)?ct::scrub_stack_to\(.*\);
    | ct::scrub_frame::<\w+>\(.*\);
    | clear_frames::<\w+>\(.*\);
    | clear_after_kernels!\(.*\);
    | [\w.]+\.wipe\(\);
    | core::ptr::write_volatile\(cp.*zero\);
    | scrub_half_a_step_down\(low\);
    | unsafe\ \{\ core::ptr::write_volatile\(slot\.as_mut_ptr\(\),\ zero\)\ \};
    )\s*$""",
    re.X,
)
GUARD = "let mut scrub = ct::ScrubOnDrop::new();"
# A guard that never runs: its destructor is what overwrites the frame.
GUARD_OFF = "let mut scrub = ::core::mem::ManuallyDrop::new(ct::ScrubOnDrop::new());"

# name | cargo profile | extra environment — most likely to notice first.
BUILDS = [
    ("release", "release", {}),
    ("dev", "dev", {}),
    (
        "unoptimised",
        "dev",
        {
            "CARGO_PROFILE_DEV_OPT_LEVEL": "0",
            "CARGO_TARGET_DIR": "target/opt0",
            "WG_PROBE_UNOPTIMISED": "1",
        },
    ),
]
PROBES = ["stack_residue", "memory_residue", "driver_residue"]

# The survivors that are understood. Keyed by file, enclosing function,
# statement, and which occurrence of that statement in that function it
# is (from 1).
WORKER = (
    "second line: inside a cipher worker, whose whole frame is overwritten "
    "once it has returned (ct::scrub_frame)"
)
COMPRESS = (
    "second line: inside the hash's compression function, whose frame is "
    "overwritten once it has returned (ct::scrub_frame)"
)
LADDER = (
    "second line: inside the curve arithmetic, whose frames are overwritten "
    "once it has returned (ct::scrub_stack_to)"
)
C_ROWS = (
    "second line: in the AVX2 kernel's frame, which its caller overwrites "
    "as a whole (clear_frames)"
)
BLANK = "second line: the place is blank whenever it gets here, and is wiped again before it is filled"
ERROR = (
    "an error path no test can take with a working entropy source and the "
    "in-tree provider; what it wipes never became a secret in use"
)
PUBLIC = (
    "a public key or a transcript hash — identity, not key material; wiped "
    "so that a value that is done with is blank"
)
CHACHA = "src/crypto/chacha20.rs"
X25519 = "src/crypto/x25519.rs"
NOISE = "src/noise.rs"
AVX2 = "simd/src/avx2.rs"
EXPECTED = {
    (CHACHA, "keystream_block", "ct::wipe_words(&mut worked);", 1): WORKER,
    (CHACHA, "block_worker", "ct::wipe_words(&mut state);", 1): WORKER,
    (CHACHA, "xor_worker", "ct::wipe(&mut ks);", 1): WORKER,
    (CHACHA, "xor_worker", "ct::wipe_words(&mut state);", 1): WORKER,
    (CHACHA, "one_time_key_worker", "ct::wipe_array(&mut block);", 1): WORKER,
    (CHACHA, "one_time_key_worker", "ct::wipe_words(&mut state);", 1): WORKER,
    (CHACHA, "seal_worker", "ct::wipe(&mut ks);", 1): WORKER,
    (CHACHA, "seal_worker", "ct::wipe_words(&mut state);", 1): WORKER,
    (CHACHA, "hchacha20_worker", "ct::wipe_words(&mut state);", 1): WORKER,
    (CHACHA, "hchacha20_worker", "ct::wipe_words(&mut worked);", 1): WORKER,
    ("src/crypto/blake2s.rs", "compress", "ct::wipe_words(&mut m);", 1): COMPRESS,
    ("src/crypto/blake2s.rs", "compress", "ct::wipe_words(&mut v);", 1): COMPRESS,
    (X25519, "encode", "ct::wipe_words(&mut words);", 1): LADDER,
    (X25519, "wipe", "ct::wipe_words(&mut self.0);", 1): LADDER,
    (X25519, "ladder", "fe.wipe();", 1): LADDER,
    (X25519, "ladder", "ct::wipe_array(&mut k);", 1): LADDER,
    (X25519, "base_ladder", "fe.wipe();", 1): LADDER,
    (X25519, "base_ladder", "ct::wipe_array(&mut k);", 1): LADDER,
    (AVX2, "eight_blocks", "core::ptr::write_volatile(cp, zero);", 1): C_ROWS,
    (AVX2, "eight_blocks", "core::ptr::write_volatile(cp.add(1), zero);", 1): C_ROWS,
    (AVX2, "eight_blocks", "core::ptr::write_volatile(cp.add(2), zero);", 1): C_ROWS,
    (AVX2, "eight_blocks", "core::ptr::write_volatile(cp.add(3), zero);", 1): C_ROWS,
    (
        "simd/src/lib.rs",
        "clear_below",
        "wireguard_sans_io::crypto::ct::scrub_stack_to(low);",
        1,
    ): "the slow way after a kernel whose frame is deeper than expected: not taken in any build this runs",
    (NOISE, "create_initiation", "state.wipe();", 1): BLANK,
    (NOISE, "identify_initiation", "identity.wipe();", 1): BLANK,
    (NOISE, "consume_initiation_finish", "consumed.wipe();", 1): BLANK,
    (NOISE, "create_response", "keys.wipe();", 1): BLANK,
    (NOISE, "consume_response", "keys.wipe();", 1): BLANK,
    ("src/session.rs", "staging", "self.staged.wipe();", 1): BLANK,
    ("src/session.rs", "write", "session.wipe();", 1): BLANK,
    ("src/tunnel.rs", "staging", "self.staged.wipe();", 1): BLANK,
    (NOISE, "create_initiation", "state.wipe();", 2): ERROR,
    (NOISE, "identify_initiation", "identity.wipe();", 2): ERROR,
    (NOISE, "consume_initiation_finish", "consumed.wipe();", 2): ERROR,
    ("src/session.rs", "discard_staged", "self.staged.wipe();", 1): ERROR,
    ("src/session.rs", "write", "self.staged.wipe();", 1): ERROR,
    ("src/tunnel.rs", "discard_staged", "self.staged.wipe();", 1): ERROR,
    ("src/tunnel.rs", "handle_transport", "ct::wipe(plaintext);", 1): ERROR,
    ("src/cookie.rs", "rotate_if_needed", "ct::wipe_array(&mut self.previous);", 1): ERROR,
    ("src/cookie.rs", "rotate_if_needed", "ct::wipe_array(&mut self.nonce_key);", 1): ERROR,
    ("src/cookie.rs", "build_cookie_reply", "ct::wipe_array(&mut encrypted);", 1): ERROR,
    ("src/cookie.rs", "build_cookie_reply", "ct::wipe_array(&mut encrypted);", 2): ERROR,
    (NOISE, "reveal_identity", "ct::wipe_array(&mut opened_static);", 1): PUBLIC,
    (NOISE, "wipe", "ct::wipe_array(&mut self.static_public);", 1): PUBLIC,
    (NOISE, "wipe", "ct::wipe_array(&mut self.hash);", 1): PUBLIC,
    (NOISE, "wipe", "ct::wipe_array(&mut self.hash);", 2): PUBLIC,
    (NOISE, "wipe", "ct::wipe_array(&mut self.static_public);", 2): PUBLIC,
    (NOISE, "wipe", "ct::wipe_array(&mut self.eph_public);", 1): PUBLIC,
    (NOISE, "wipe", "ct::wipe_array(&mut self.hash);", 3): PUBLIC,
    (
        "src/crypto/poly1305.rs",
        "wipe",
        "ct::wipe_words(&mut self.r);",
        2,
    ): "the limbs for 32-bit targets: not the code a 64-bit machine runs",
    (
        "src/crypto/poly1305.rs",
        "wipe",
        "ct::wipe_words(&mut self.h);",
        2,
    ): "the limbs for 32-bit targets: not the code a 64-bit machine runs",
    (
        "src/crypto/poly1305.rs",
        "wipe",
        "ct::wipe_words(&mut self.pad);",
        2,
    ): "the limbs for 32-bit targets: not the code a 64-bit machine runs",
    (
        "src/crypto/poly1305.rs",
        "wipe",
        "ct::wipe(&mut self.buf);",
        1,
    ): "holds the last bytes of the message, which is ciphertext",
    (
        "src/index.rs",
        "draw_key",
        "ct::wipe_array(&mut bytes);",
        1,
    ): "the key of the session indices: not treated as a secret of this kind (README, Secrets in memory)",
}


def statements():
    """Every statement to remove: (key, description, path, line number, replacement)."""
    found = []
    for path in FILES:
        if path.name in SKIP_FILES:
            continue
        lines = path.read_text(encoding="utf-8").split("\n")
        relative = str(path.relative_to(ROOT))
        function = "?"
        seen = {}
        for number, line in enumerate(lines, start=1):
            # The test module at the end of a file is not library code.
            if (
                re.match(r"^(pub\(crate\) )?mod tests \{", line)
                and number > 1
                and "cfg(test)" in lines[number - 2]
            ):
                break
            named = re.match(r"^\s*(?:pub(?:\([a-z]+\))? )?(?:const )?(?:unsafe )?fn (\w+)", line)
            if named:
                function = named.group(1)
            # (A macro at the top level is a scope of its own; one that
            # is defined inside a function belongs to that function.)
            macro = re.match(r"^macro_rules! (\w+)", line)
            if macro:
                function = macro.group(1) + "!"
            text = line.strip()
            if STATEMENT.match(line):
                replacement = ""
            elif text == GUARD:
                replacement = line.replace(GUARD, GUARD_OFF)
            else:
                continue
            occurrence = seen[(function, text)] = seen.get((function, text), 0) + 1
            key = (relative, function, text, occurrence)
            what = f"{relative}: {function}: {text}" + (f" (#{occurrence})" if occurrence > 1 else "")
            found.append((key, what, relative, number, replacement))
    return found


def run(cmd, cwd, env_extra, jobs):
    env = dict(os.environ)
    env.update(env_extra)
    env["CARGO_BUILD_JOBS"] = str(jobs)
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)


def check(copy, jobs):
    """Do the probes pass on this copy? -> ("pass" | "caught" | "broken", detail)"""
    probes = copy / "probes"
    for name, profile, env in BUILDS:
        built = run(["cargo", "build", "--quiet", "--profile", profile, "--bins"], probes, env, jobs)
        if built.returncode != 0:
            return "broken", (built.stderr or built.stdout)[-800:]
        for probe in PROBES:
            ran = run(["cargo", "run", "--quiet", "--profile", profile, "--bin", probe], probes, env, jobs)
            if ran.returncode != 0:
                lines = (ran.stdout + ran.stderr).splitlines()
                marks = ("LEFT ON THE STACK", "LEFT IN IT", "BYTES LEFT", "FAIL", "panicked")
                hit = next((l.strip() for l in lines if any(m in l for m in marks)), "")
                return "caught", f"{probe}, {name} build: {hit[:160]}"
    return "pass", ""


def worker(index, mine, jobs, verbose):
    """One copy of the repository; the removals in `mine`, one after another."""
    scratch = pathlib.Path(tempfile.mkdtemp(prefix=f"wipes-{index}-"))
    copy = scratch / "repo"
    results = []
    try:
        subprocess.run(
            ["rsync", "-a", "--exclude", "target", "--exclude", ".git", f"{ROOT}/", f"{copy}/"],
            check=True,
        )
        verdict, detail = check(copy, jobs)
        if verdict != "pass":
            return [(None, "baseline", verdict, detail)]
        for key, what, relative, number, replacement in mine:
            path = copy / relative
            original = path.read_text(encoding="utf-8")
            lines = original.split("\n")
            lines[number - 1] = replacement
            try:
                path.write_text("\n".join(lines), encoding="utf-8")
                # A build system that goes by modification times has to
                # see a new one.
                time.sleep(1.2)
                verdict, detail = check(copy, jobs)
            finally:
                path.write_text(original, encoding="utf-8")
                time.sleep(1.2)
            results.append((key, what, verdict, detail))
            if verbose:
                print(f"  {verdict:7} {what}", flush=True)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 4) // 6))
    parser.add_argument("--only", default="")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()

    found = statements()
    keys = {key for key, *_ in found}
    stale = [key for key in EXPECTED if key not in keys]
    if stale:
        for key in stale:
            print("EXPECTED names a statement that is not there any more:", key)
        return 1
    if args.list:
        for key, what, *_ in found:
            print(("expected to survive: " if key in EXPECTED else "must be caught:      ") + what)
        print(f"{len(found)} statements, {len(EXPECTED)} of them expected to survive")
        return 0
    chosen = [f for f in found if args.only in f[1]]
    if not chosen:
        print("nothing matches --only")
        return 1

    jobs = max(1, min(args.jobs, len(chosen)))
    cargo_jobs = max(1, (os.cpu_count() or 4) // jobs)
    print(f"{len(chosen)} removals, {jobs} at a time", flush=True)
    with concurrent.futures.ThreadPoolExecutor(jobs) as pool:
        futures = [
            pool.submit(worker, i, chosen[i::jobs], cargo_jobs, True) for i in range(jobs)
        ]
        results = [r for f in futures for r in f.result()]

    failed = False
    caught = 0
    for key, what, verdict, detail in results:
        if key is None:
            print(f"The probes do not pass on an unchanged copy ({verdict}): {detail}")
            return 2
        expected = key in EXPECTED
        if verdict == "broken":
            print(f"DOES NOT BUILD without it (this script's defect): {what}\n{detail}")
            failed = True
        elif verdict == "caught":
            caught += 1
            if expected:
                print(f"CAUGHT, though listed as surviving — take it off the list: {what}\n    {detail}")
                failed = True
        elif not expected:
            print(f"SURVIVED: the probes do not notice the removal of {what}")
            failed = True
    survived = sum(1 for key, _, verdict, _ in results if verdict == "pass")
    print(
        f"{caught} of {len(results)} removals make the residue check fail; "
        f"{survived} survive, as listed"
        + ("" if not failed else " — and see above")
    )
    if failed:
        return 1
    print("PASS: every wipe is either seen by the probes or listed with its reason.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
