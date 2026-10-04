# Toolchain fingerprints: web page

Will a binary built by toolchain X run on target Y? This page matches the
toolchains recorded by [toolchain-fingerprints](https://github.com/devm18426/toolchain-fingerprints)
against the facts you give about your target, and tells you which will run.

## Using it

Fill in what you know about the target: loader, `/lib` sonames, `uname -r`,
endianness, machine, ELF class, glibc version and binary format (ELF, or bFLT
on no-MMU uClinux). Or paste the output of `readelf -h -l -d` or `file` on a
binary that already runs there, plus `ls /lib` and `uname -r`. Rules only fire for the facts you gave.

| verdict | when |
|---|---|
| NO | ELF binaries on a bFLT target or bFLT binaries on an ELF one; wrong endianness or machine family; ELF64 binaries on an ELF32 userland; a different loader; a library every binary needs is missing; libc uses only `*_time64` syscalls and the kernel is older than 5.1; the kernel is below glibc's minimum; the program needs newer `GLIBC_` symbols than the target has |
| RISKY | 32-bit binaries on a 64-bit target; a library that typical programs (pthreads, `select`, `dlopen`, libm) pull in is missing, e.g. `ld-uClibc.so.1`; only `DT_GNU_HASH` against a uClibc loader |
| INFO | libc uses `*_time64` with fallback; kernel headers newer than the target kernel; ELF-only checks skipped for a bFLT toolchain |

Toolchains whose compiler ran but compiled nothing (`probe.status` other than
`ok`) get no verdict: they are marked as such, with the compiler error, and
their compiler-derived columns show `—`. bFLT toolchains likewise show `—` for
the ELF fields their records cannot have.

## Running it locally

```sh
npm test
node scripts/fetch-data.mjs
python -m http.server 8766 --directory site
```

Then open http://localhost:8766/.
