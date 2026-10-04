// npm test  (node --test)
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { matchRecord, parseTargetText, schemaProblem, newerDataNote, vcmp, COLS, cell, fmt, extraCols, machineFamily, imageRef, verdictRank,
         KNOWN_MINOR, SUPPORTED_MAJOR, placeholder, shown, recordFamily, skipResult, targetFormat } from "../site/matcher.js";

const load = p => JSON.parse(readFileSync(new URL(p, import.meta.url), "utf8"));
const fixture = load("./fixtures/fingerprints.json");
const byId = Object.fromEntries(fixture.toolchains.map(r => [r.tc_id, r]));

const target = facts => ({interp: "", kernel: "", endian: "", machine: "", glibc: "",
                          ...facts, provides: new Set(facts.provides || [])});

// An old embedded target: Linux 3.18, big-endian MIPS, uClibc loader .so.0
const OLD_MIPS = target({interp: "/lib/ld-uClibc.so.0", provides: ["libc.so.0", "ld-uClibc.so.0"],
                       kernel: "3.18.140", endian: "big", machine: "MIPS R3000"});

test("old MIPS target: 2017.11 uClibc runs, 2026.08 uClibc fails on time64", () => {
  const old = matchRecord(byId["mips32-uclibc-2017.11"], OLD_MIPS);
  assert.equal(old.verdict, "OK");
  const neu = matchRecord(byId["mips32-uclibc-2026.08"], OLD_MIPS);
  assert.equal(neu.verdict, "NO");
  assert.match(neu.reasons[0].text, /_time64/);
  assert.ok(neu.reasons.some(r => r.level === "RISKY" && r.text.includes("ld-uClibc.so.1")));
});

test("wrong endianness and machine are NO", () => {
  const r = matchRecord(byId["armv7-eabihf-musl-2026.08"], OLD_MIPS);
  assert.equal(r.verdict, "NO");
  assert.ok(r.reasons.some(x => x.text.includes("little-endian")));
});

test("musl libc.so is satisfied by the musl loader", () => {
  const t = target({interp: "/lib/ld-musl-mips.so.1"});
  assert.equal(matchRecord(byId["mips32-musl-2026.08"], {...t, provides: new Set(["ld-musl-mips.so.1"])}).verdict, "OK");
});

test("glibc: minimum kernel and symbol versions", () => {
  const r = matchRecord(byId["mips32-glibc-2026.08"],
                        target({interp: "/lib/ld.so.1", provides: ["libc.so.6", "libm.so.6"], kernel: "3.0.8", glibc: "2.19"}));
  assert.equal(r.verdict, "NO");
  assert.ok(r.reasons.some(x => x.text.includes("kernel too old")));
  assert.ok(r.reasons.some(x => x.text.includes("GLIBC_2.34")));
});

test("no target facts means no verdict", () => {
  assert.equal(matchRecord(byId["mips32-musl-2026.08"], target({})), null);
});

test("parseTargetText reads readelf, ls and uname output", () => {
  const f = parseTargetText(`  Data:     2's complement, big endian
  Machine:  MIPS R3000
      [Requesting program interpreter: /lib/ld-uClibc.so.0]
 0x00000001 (NEEDED)  Shared library: [libc.so.0]
libc.so.0  ld-uClibc.so.0  libc-2.19.so
3.18.140`);
  assert.deepEqual({...f, sonames: [...f.sonames].sort()}, {
    interp: "/lib/ld-uClibc.so.0", endian: "big", machine: "MIPS R3000", kernel: "3.18.140", glibc: "2.19",
    sonames: ["ld-uClibc.so.0", "libc-2.19.so", "libc.so.0"],
  });
});

test("schema contract: accepts 2.x, refuses other majors", () => {
  assert.equal(schemaProblem(fixture), null);
  assert.match(schemaProblem({schema_version: "3.0", toolchains: []}), /only understands 2\.x/);
  assert.ok(schemaProblem({}));
});

test("vcmp compares dotted versions numerically", () => {
  assert.ok(vcmp("3.18.140", "5.1") < 0);
  assert.ok(vcmp("2.34", "2.4") > 0);
  assert.equal(vcmp("5.1", "5.1.0"), 0);
});

// Runs against whatever scripts/fetch-data.mjs put next to the page (CI always fetches first).
const live = new URL("../site/fingerprints.json", import.meta.url);
test("pinned dataset: loads, unique ids, every rule runs on every record", { skip: !existsSync(live) && "no site/fingerprints.json" }, () => {
  const doc = JSON.parse(readFileSync(live, "utf8"));
  assert.equal(schemaProblem(doc), null);
  const ids = doc.toolchains.map(r => r.tc_id);
  assert.equal(new Set(ids).size, ids.length);
  const profiles = [OLD_MIPS, target({interp: "/lib/ld-linux-armhf.so.3", provides: ["libc.so.6"], kernel: "6.1",
                                    endian: "little", machine: "ARM", glibc: "2.36"})];
  for (const r of doc.toolchains){
    for (const t of profiles) assert.ok(["OK", "RISKY", "NO"].includes(matchRecord(r, t).verdict), r.tc_id);
    for (const [k] of COLS) fmt(shown(r, k));   // every column resolves without throwing
  }
  // a dataset this page was written for needs no extra columns and no "newer" note
  if (+doc.schema_version.split(".")[1] <= KNOWN_MINOR){
    assert.deepEqual(extraCols(doc.toolchains), []);
    assert.equal(newerDataNote(doc), null);
  }
});

// ---- forward compatibility: data from a later 2.x generator ------------------
test("a newer 2.x record with unknown fields and enum values still matches", () => {
  const base = byId["mips32-uclibc-2026.08"];
  const future = {
    ...base,
    some_future_field: {x: 1},
    libc: {...base.libc, kind: "bionic"},
    time: {...base.time, time64_syscalls: "partial"},
    float_abi: "quad",
    hash_style: "gnu+dt_relr",
    arch: {family: "loongarch", abi: {lp64: "d", new_flag: true}},
  };
  const r = matchRecord(future, OLD_MIPS);
  assert.ok(["OK", "RISKY", "NO"].includes(r.verdict));
  assert.ok(!r.reasons.some(x => /_time64/.test(x.text)));   // unknown value: no time64 rule fires
  for (const [k] of COLS) fmt(cell(future, k));
  assert.equal(fmt(cell(future, COLS.find(c => c[1] === "arch ABI")[0])), "lp64=d, new_flag=true");
});

test("older 2.1/2.2 records without arch fall back to mips/arm", () => {
  const {arch, ...old} = byId["mips32-uclibc-2017.11"];
  const col = name => COLS.find(c => c[1] === name)[0];
  assert.equal(cell(old, col("arch")), "mips");
  assert.match(fmt(cell(old, col("arch ABI"))), /isa_level=mips32/);
  const {needed_corpus, time, kernel, arch: _a, mips, ...v20} = byId["mips32-uclibc-2017.11"];
  assert.ok(matchRecord(v20, OLD_MIPS));                        // 2.0-shaped record: no crash
});

test("newer minor versions load with a note; newer majors are refused", () => {
  assert.equal(schemaProblem({schema_version: "2.9", toolchains: []}), null);
  assert.match(newerDataNote({schema_version: "2.9"}), /newer than this page/);
  assert.equal(newerDataNote(fixture), null);
  assert.ok(schemaProblem({schema_version: "3.0", toolchains: []}));
});

// ---- machine families, ELF class, robustness, unknown fields ----------------
test("machine names from readelf, uname -m and arch.family agree", () => {
  for (const [name, fam] of [["MIPS R3000", "mips"], ["mipsel", "mips"], ["mips64", "mips"], ["ARM", "arm"],
                             ["armv7l", "arm"], ["AArch64", "aarch64"], ["arm64", "aarch64"],
                             ["Advanced Micro Devices X86-64", "x86_64"], ["x86_64", "x86_64"], ["Intel 80386", "x86"],
                             ["i686", "x86"], ["RISC-V", "riscv"], ["riscv64", "riscv"], ["PowerPC64", "power"],
                             ["ppc64le", "power"], ["LoongArch", "loongarch"], ["IBM S/390", "s390"],
                             ["s390x", "s390"], ["Renesas / SuperH SH", "sh"], ["sh4", "sh"],
                             ["Tensilica Xtensa Processor", "xtensa"], ["Some Future CPU", "some"],
                             ["Tilera TILE-Gx multicore architecture family", "tilegx"], ["tilegx", "tilegx"],
                             ["Tilera TILEPro multicore architecture family", "tilepro"], ["tilepro", "tilepro"],
                             ["Intel IA-64", "ia64"], ["ia64", "ia64"], ["Alpha", "alpha"], ["alpha", "alpha"],
                             ["HPPA", "parisc"], ["parisc", "parisc"], ["parisc64", "parisc"]])
    assert.equal(machineFamily(name), fam, name);
  const mips = byId["mips32-uclibc-2017.11"];
  assert.equal(matchRecord(mips, target({machine: "mips"})).verdict, "OK");
  const arm = byId["armv7-eabihf-musl-2026.08"];
  assert.equal(matchRecord(arm, target({machine: "armv7l"})).verdict, "OK");
  assert.equal(matchRecord(arm, target({machine: "mips"})).verdict, "NO");
  // 32-bit ARM on a 64-bit ARM target may work: RISKY, not NO
  const onA64 = matchRecord(arm, target({machine: "aarch64"}));
  assert.equal(onA64.verdict, "RISKY");
  assert.match(onA64.reasons[0].text, /32-bit/);
});

test("ELF class: 64-bit binaries on a 32-bit userland are NO, the reverse is RISKY", () => {
  const m32 = byId["mips32-musl-2026.08"];
  const m64 = {...m32, elf: {...m32.elf, class: "64"}};
  assert.equal(matchRecord(m64, target({machine: "MIPS R3000", class: "ELF32"})).verdict, "NO");
  assert.equal(matchRecord(m32, target({machine: "MIPS R3000", class: "ELF64"})).verdict, "RISKY");
  assert.equal(matchRecord(m32, target({class: "ELF32"})).verdict, "OK");
  assert.equal(parseTargetText("  Class:                             ELF64\n").class, "ELF64");
});

test("a record that breaks a rule gets RISKY instead of breaking every verdict", () => {
  const {ldso, needed_corpus, ...broken} = byId["mips32-uclibc-2017.11"];
  const bad = {...broken, elf: null};
  const r = matchRecord(bad, OLD_MIPS);
  assert.ok(["RISKY", "NO"].includes(r.verdict));
  assert.ok(r.reasons.some(x => /could not run/.test(x.text)));
  assert.equal(matchRecord(byId["mips32-uclibc-2017.11"], OLD_MIPS).verdict, "OK");
});

test("fields no column covers become extra columns; known subtrees do not", () => {
  const rec = {...byId["mips32-uclibc-2017.11"], new_top: 1, new_obj: {a: "x", b: {c: true}},
               arch: {family: "mips", abi: {brand_new: 1}}, raw: {extra: "y"}};
  const extra = extraCols([rec, byId["mips32-glibc-2026.08"]]).map(c => c[0]);
  assert.deepEqual(extra, ["new_top", "new_obj.a", "new_obj.b.c"]);
  assert.deepEqual(extraCols(fixture.toolchains), []);          // everything current has a column
});

test("imageRef pins the probed image by tag and digest", () => {
  const d = "sha256:" + "a".repeat(64);
  assert.equal(imageRef({tc_id: "x-1", provenance: {image_digest: "ghcr.io/o/r@" + d}}), "ghcr.io/o/r:x-1@" + d);
  assert.equal(imageRef({tc_id: "x-1", provenance: {}}), "");
  assert.equal(imageRef({tc_id: "x-1"}), "");
});

test("verdicts order OK, RISKY, NO, unmatched records, then rows without a verdict", () => {
  const ranks = ["NO", "OK", undefined, "RISKY", "SKIP"].map(v => verdictRank(v && {verdict: v}));
  assert.deepEqual(ranks, [2, 0, 4, 1, 3]);
});

// ---- schema 2.4: probe status -----------------------------------------------
const FAILED = {...byId["mips32-uclibc-2026.08"], probe: {status: "compile_failed", error: "cc1: error while loading shared libraries: libmpc.so.3"}};

test("compile_failed records are never matched and show the compiler error", () => {
  for (const t of [OLD_MIPS, target({}), target({machine: "mips"})]){
    const r = matchRecord(FAILED, t);
    assert.equal(r.verdict, "SKIP");
    assert.equal(r.label, "compile failed");
    assert.match(r.reasons[0].text, /compiled nothing.*libmpc\.so\.3/);
  }
  assert.deepEqual(skipResult(FAILED), matchRecord(FAILED, OLD_MIPS));
  assert.equal(skipResult(byId["mips32-uclibc-2026.08"]), null);              // no probe field (pre-2.4): ok
  assert.equal(skipResult({...FAILED, probe: {status: "ok", error: ""}}), null);
  // a status this page does not know is not matched either
  assert.equal(matchRecord({...FAILED, probe: {status: "timed_out", error: ""}}, OLD_MIPS).verdict, "SKIP");
});

test("compile_failed records show placeholders as such, but keep real fields", () => {
  const col = name => COLS.find(c => c[1] === name)[0];
  for (const name of ["endian", "class", "interp", "needed (minimal)", "time_t bits", "dynamic", "-march", "arch"])
    assert.ok(placeholder(FAILED, col(name)), name);
  for (const name of ["toolchain", "triple", "gcc", "libc", "libc ver", "probe"])
    assert.equal(placeholder(FAILED, col(name)), "", name);
  assert.equal(fmt(shown(FAILED, "elf.endian")), "—");
  assert.equal(fmt(shown(FAILED, "probe.status")), "compile_failed");
});

// ---- schema 2.5: bFLT binaries of no-MMU toolchains ----------------------------
// Shaped like a 2.5 record: no ELF header, so elf.* are placeholders (endian "big" on a little-endian ARM).
const BFLT = {...byId["armv7-eabihf-musl-2026.08"], tc_id: "armv7m-uclibc-x", triple: "arm-buildroot-uclinux-uclibcgnueabi",
              libc: {kind: "uclibc", soname: "", version: "1.0.59"}, ldso: {soname: ""}, interp: "",
              elf: {class: "32", endian: "big", machine: ""}, isa: "", needed: [], needed_corpus: [], hash_style: "none",
              time: {time_t_bits: 32, time64_syscalls: "none"}, kernel: {headers: "4.9.61", min: ""},
              probe: {status: "ok", error: ""}, binary: {format: "bflt"}, arch: {family: "unknown", abi: {}}};

test("bFLT records: machine family comes from the triple; ELF placeholders are not facts", () => {
  assert.equal(recordFamily(BFLT), "arm");
  assert.equal(fmt(cell(BFLT, COLS.find(c => c[1] === "arch")[0])), "arm");
  assert.equal(fmt(shown(BFLT, "elf.endian")), "—");
  assert.equal(fmt(shown(BFLT, "interp")), "—");
  assert.equal(fmt(shown(BFLT, "binary.format")), "bflt");
  assert.equal(fmt(shown(BFLT, "libc.version")), "1.0.59");                     // uClibc version shown
  assert.equal(fmt(cell({...BFLT, binary: {format: "bflt", bflt: {version: 4, flags: ["ram", "gotpic"]}}},
                        COLS.find(c => c[1] === "bFLT header")[0])), "v4 ram,gotpic");
});

test("bFLT binaries do not run on ELF targets, and ELF binaries do not run on bFLT targets", () => {
  // a loader or an ELF class means the target runs ELF
  for (const t of [target({interp: "/lib/ld-uClibc.so.0"}), target({class: "ELF32"}), target({format: "ELF", machine: "arm"})]){
    const r = matchRecord(BFLT, t);
    assert.equal(r.verdict, "NO");
    assert.match(r.reasons[0].text, /bFLT/);
  }
  const NOMMU = target({format: "bFLT", machine: "arm", endian: "little", kernel: "4.9.0"});
  const ok = matchRecord(BFLT, NOMMU);
  assert.equal(ok.verdict, "OK");                                              // placeholder endian "big" did not fire
  assert.ok(ok.reasons.some(x => x.level === "INFO" && /no ELF header/.test(x.text)));
  assert.equal(matchRecord(BFLT, {...NOMMU, machine: "m68k"}).verdict, "NO");
  const elf = matchRecord(byId["armv7-eabihf-musl-2026.08"], NOMMU);
  assert.equal(elf.verdict, "NO");
  assert.ok(elf.reasons.some(x => /target runs bFLT/.test(x.text)));
  // pre-2.5 records have no binary field and are ELF
  assert.equal(matchRecord(byId["mips32-uclibc-2017.11"], target({format: "bflt"})).verdict, "NO");
  // a format this page does not know: ELF rules are skipped, so it cannot be OK
  const unk = matchRecord({...BFLT, binary: {format: "pe"}}, target({endian: "little"}));
  assert.equal(unk.verdict, "RISKY");
  assert.equal(matchRecord({...BFLT, binary: {format: "pe"}}, target({format: "bflt"})).verdict, "OK");
});

test("target format: given, implied by ELF-only facts, or unknown", () => {
  assert.equal(targetFormat(target({format: "BFLT"})), "bflt");
  assert.equal(targetFormat(target({format: "flat"})), "bflt");
  assert.equal(targetFormat(target({format: "elf32"})), "elf");
  assert.equal(targetFormat(target({interp: "/lib/ld.so.1"})), "elf");
  assert.equal(targetFormat(target({endian: "big"})), "");
  assert.equal(targetFormat(target({format: "something else", interp: "/lib/ld.so.1"})), "");
  assert.equal(parseTargetText("/bin/sh: BFLT executable - version 4 ram gotpic\n").format, "bFLT");
  assert.equal(parseTargetText("ELF Header:\n  Class:  ELF32\n").format, "ELF");
  assert.equal(parseTargetText("busybox: ELF 32-bit MSB executable, MIPS").format, "ELF");
  assert.equal(parseTargetText("3.18.140").format, undefined);
});

test("2.4/2.5 fields have columns; fields added under them later still become extra columns", () => {
  const rec = {...BFLT, binary: {format: "bflt", bflt: {version: 4, flags: []}, future: 1},
               probe: {status: "ok", error: "", future: 2}};
  assert.deepEqual(extraCols([rec]).map(c => c[0]).sort(), ["binary.future", "probe.future"]);
  assert.equal(KNOWN_MINOR, 5);
  assert.equal(newerDataNote({schema_version: `${SUPPORTED_MAJOR}.5`}), null);
  assert.match(newerDataNote({schema_version: `${SUPPORTED_MAJOR}.6`}), /newer than this page \(2\.5\)/);
});
