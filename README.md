# Toolchain fingerprints: web page

A static page that answers *will a binary built by toolchain X run on target Y?*
It reads a dataset published by
[toolchain-fingerprints](https://github.com/devm18426/toolchain-fingerprints)
and matches each toolchain against the facts you give about your target.

## How it gets its data

`data.lock` pins one release of the toolchain repo, by tag and sha256:

1. The toolchain repo cuts a `data-<schema>.<n>` release and sends this repo a
   `data-release` dispatch.
2. `bump-data.yml` pins `data.lock` to it, runs the tests against the new data,
   and opens a PR that auto-merges when `test` passes.
3. `ci.yml` on `main` downloads exactly the pinned file, checks its sha256 and
   schema major version, tests, and deploys `site/` to GitHub Pages with the
   JSON next to the page.

A schema major bump (3.x) fails the bump PR's tests until the page supports it.
Meanwhile the site keeps serving the last good dataset.

## Develop

```sh
npm test                                                        # matcher tests (no dependencies)
node scripts/fetch-data.mjs                                     # the pinned release -> site/
node scripts/fetch-data.mjs --from ../toolchain-fingerprints/data/fingerprints.json   # local data
python -m http.server 8766 --directory site                     # then open http://localhost:8766/
```

`site/matcher.js` holds all matching logic (no DOM). `site/index.html` is only the UI.

## What the matcher checks

Fill in what you know about the target (loader, `/lib` sonames, `uname -r`,
endianness, machine, ELF class, glibc version). You can also paste `readelf -h -l -d`,
`ls /lib` and `uname -r` output. Rules only fire for facts you gave.

Machine names are compared by family, so readelf's `Machine` (`AArch64`,
`Advanced Micro Devices X86-64`), `uname -m` (`aarch64`, `x86_64`) and the
dataset's `arch.family` all match each other. A machine the page does not know
is compared by the first word of its name, which is how the generator names
families it does not know.

| verdict | when |
|---|---|
| NO | wrong endianness or machine family; ELF64 binaries on an ELF32 userland; different loader; a `hello` NEEDED lib missing; libc uses only `*_time64` syscalls and the kernel is older than 5.1; the kernel is below glibc's minimum; the program needs newer `GLIBC_` symbols than the target has |
| RISKY | 32-bit binaries on a 64-bit target (i386 on x86-64, ARM on AArch64, or ELF32 on an ELF64 userland); a check that could not run on a malformed record; a library that real programs (pthreads, `select`, `dlopen`, libm) pull in is missing, e.g. `ld-uClibc.so.1`; only `DT_GNU_HASH` against a uClibc loader |
| INFO | libc uses `*_time64` with fallback; kernel headers newer than the target kernel |

The page refuses a dataset whose schema major version it does not know. Newer
minor versions load with a note: unknown fields are ignored, and unknown enum
values never trigger a rule. Fields no column covers appear as extra columns at
the right of the table, as-is. `KNOWN_MINOR` in `site/matcher.js` records the
newest 2.x the page was written against.

One-time GitHub setup (Pages, the App, auto-merge) is in the toolchain repo's
`docs/SETUP.md`.
