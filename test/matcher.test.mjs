// npm test  (node --test)
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { matchRecord, parseTargetText, schemaProblem, newerDataNote, vcmp, COLS, cell, fmt } from "../site/matcher.js";

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
    for (const [k] of COLS) fmt(cell(r, k));    // every column resolves without throwing
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
