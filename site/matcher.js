// Pure matcher logic: no DOM. Imported by index.html and by the tests.
// ---- contract ------------------------------------------------------------
export const SUPPORTED_MAJOR = 2;           // refuse any other major version of the schema
export const KNOWN_MINOR = 5;               // newest 2.x this page was written against
// Forward compatibility: within 2.x, fields are only added. This page ignores
// fields it does not know, treats enum values it does not know as unknown (no
// rule fires on them), shows "—" for fields older data does not have, and
// lists fields it does not know as extra columns (see extraCols).

// ---- field helpers -------------------------------------------------------
export const get = (r, path) => path.split(".").reduce((o, k) => (o == null ? o : o[k]), r);
export const base = p => (p || "").split("/").pop();
export const splitList = s => (s || "").split(/[,\s]+/).map(x => x.trim()).filter(Boolean);
export const fmt = v => v === "" || v == null ? "—" : Array.isArray(v) ? (v.length ? v.join(", ") : "—")
               : typeof v === "object" ? (Object.keys(v).length ? Object.entries(v).map(([k, x]) => `${k}=${x}`).join(", ") : "—")
               : typeof v === "boolean" ? (v ? "yes" : "no") : String(v);

// ---- table columns: [schema field path, header, css class] -------------
// Adding a schema field to the table is one line here. A column key is a field
// path, or a function for values that need a fallback for older data. Fields added in a
// minor schema version may be missing from older data; they show as "—".
export const COLS = [
  ["tc_id", "toolchain"], ["triple", "triple"], ["libc.kind", "libc"],
  ["libc.version", "libc ver"], ["gcc_version", "gcc"],
  ["elf.machine", "machine"], ["elf.class", "class"], ["elf.endian", "endian"], ["march", "-march"], ["isa", "isa"],
  ["float_abi", "float"], [archFamily, "arch"], [archAbi, "arch ABI"],
  ["time.time_t_bits", "time_t bits"], ["time.time64_syscalls", "time64 syscalls"],
  ["kernel.headers", "kernel headers"], ["kernel.min", "min kernel"],
  ["glibc.requires", "needs GLIBC_"], ["glibc.provides", "has GLIBC_"],
  ["pie_default", "PIE"], ["hash_style", "hash"], ["interp", "interp"],
  ["needed", "needed (minimal)"], ["needed_corpus", "needed (typical)"],
  ["ldso.soname", "ldso soname"], ["libc.soname", "libc soname"],
  ["dynamic_ok", "dynamic"], ["static_ok", "static"], ["cxx_ok", "C++"],
  ["sysroot_sonames", "sysroot sonames", "list"],
  ["binary.format", "format"], [bfltHeader, "bFLT header"], ["probe.status", "probe"],
];

// Field paths the curated columns already cover (whole subtrees for prefixes),
// plus subtrees that are never shown as columns.
// probe.error is shown in the "why" column rather than as a column.
const COVERED = ["arch", "mips", "arm", "raw", "provenance", "probe.error"];

// Leaf fields in the data that no column covers, e.g. fields added by a newer
// 2.x generator. Returned in COLS shape so the page can append them to the table.
export function extraCols(records){
  const known = new Set(COLS.flatMap(([k]) => typeof k === "string" ? [k] : k.covers || []));
  const covered = path => known.has(path) || COVERED.some(p => path === p || path.startsWith(p + "."));
  const found = new Set();
  const walk = (v, path) => {
    if (covered(path)) return;
    if (v && typeof v === "object" && !Array.isArray(v) && Object.keys(v).length)
      for (const k of Object.keys(v)) walk(v[k], path + "." + k);
    else found.add(path);
  };
  for (const r of records) for (const k of Object.keys(r || {})) walk(r[k], k);
  return [...found].map(path => [path, path, "extra"]);
}

// arch/arch.abi arrived in 2.3; 2.1-2.2 data only has the mips/arm objects
function archFamily(r){ return recordFamily(r); }
function archAbi(r){ return r.arch ? r.arch.abi : r.mips || r.arm || null; }
// binary.bflt (2.5) is only there when the probe captured the file's header
function bfltHeader(r){
  const h = r.binary && r.binary.bflt;
  return h ? `v${h.version}` + (Array.isArray(h.flags) && h.flags.length ? " " + h.flags.join(",") : "") : "";
}
bfltHeader.covers = ["binary.bflt.version", "binary.bflt.flags"];
export const cell = (r, key) => typeof key === "function" ? key(r) : get(r, key);

// ---- records whose fields are placeholders ------------------------------------
// probe (2.4): a toolchain whose compiler ran but compiled nothing has
// placeholder values in every field derived from compiler output. Any status
// other than "ok" (including ones this page does not know) is not matched.
// Records from before 2.4 have no probe field and count as ok.
export function probeFailure(r){
  const p = r && r.probe;
  return p && p.status !== "ok" ? {status: String(p.status || "unknown"), error: p.error || ""} : null;
}
// binary.format (2.5): "elf", "bflt" (uClinux flat, no-MMU targets) or "unknown".
// Records from before 2.5 were all read by readelf, so they are ELF.
export const recordFormat = r => r && r.binary ? String(r.binary.format || "unknown") : "elf";

const COMPILE_DERIVED = ["elf", "interp", "needed", "needed_corpus", "dynamic_ok", "static_ok", "cxx_ok",
                         "time", "hash_style", "march", "pie_default", "float_abi", "isa", "arch"];
const ELF_DERIVED = ["elf", "interp", "needed", "hash_style", "pie_default", "isa"];
// Why this record's value for column key is a placeholder rather than a fact, or "".
export function placeholder(r, key){
  const path = typeof key === "function" ? (key === archFamily || key === archAbi ? "arch" : "") : key;
  const under = list => list.some(p => path === p || path.startsWith(p + "."));
  const f = probeFailure(r);
  if (f && under(COMPILE_DERIVED)) return `placeholder: the probe status is ${f.status}, so nothing was compiled`;
  if (recordFormat(r) !== "elf" && under(ELF_DERIVED))
    return `not recorded: ${recordFormat(r)} binaries have no ELF header`;
  return "";
}
// The value the table shows: placeholders show as "—".
export const shown = (r, key) => placeholder(r, key) ? "" : cell(r, key);

// ---- images and verdict order ------------------------------------------------
// The image a record was probed from, as tag@digest: readable, and pinned to
// exactly the image the record describes even if the tag later moves.
export function imageRef(r){
  const d = r && r.provenance && r.provenance.image_digest;
  const m = /^(.+)@(sha256:[0-9a-f]{64})$/.exec(d || "");
  return m ? `${m[1]}:${r.tc_id}@${m[2]}` : "";
}

// Best verdict first, then records that could not be matched, then rows without a verdict.
export const VERDICT_ORDER = ["OK", "RISKY", "NO", "SKIP"];
export const verdictRank = res => res ? VERDICT_ORDER.indexOf(res.verdict) : VERDICT_ORDER.length;

// ---- grouping by target ABI --------------------------------------------------
// The page shows one row per target ABI: the facts that decide whether a binary
// can start on a device at all. They come from fields every record has, so a
// toolchain joins its group whatever its origin (a Bootlin release, built from
// source, a vendor SDK). Placeholder fields count as unknown; records that are
// not matched (probe failed) group by their probe status instead.
const ABI_FIELDS = ["elf.endian", "elf.class", "libc.kind", "interp", "float_abi"];
export function abiKey(r){
  const f = probeFailure(r);
  if (f) return "unmatched|" + f.status;
  return [recordFamily(r), recordFormat(r), ...ABI_FIELDS.map(k => fmt(shown(r, k)))].join("|");
}
// Records grouped by abiKey, each group's records oldest gcc first.
export function groupByAbi(records){
  const groups = new Map();
  for (const r of records){
    const k = abiKey(r);
    if (!groups.has(k)) groups.set(k, {key: k, records: []});
    groups.get(k).records.push(r);
  }
  const byGcc = (a, b) => vcmp(a.gcc_version, b.gcc_version) || a.tc_id.localeCompare(b.tc_id);
  return [...groups.values()].map(g => (g.records.sort(byGcc), g));
}
// A group's verdict is its best record's; resultOf(r) gives a record's result or null.
export const groupRank = (g, resultOf) => Math.min(...g.records.map(r => verdictRank(resultOf(r))));
// Short names for a group: what it is, and the ABI details under it.
export function abiLabel(g){
  const r = g.records[0], f = probeFailure(r);
  if (f) return {name: `${f.status.replace(/_/g, " ")}`, detail: "not matched: the probe could not compile with these toolchains"};
  const fmtName = recordFormat(r) === "elf" ? "" : recordFormat(r) === "bflt" ? "bFLT" : recordFormat(r);
  const name = [recordFamily(r) || "unknown arch", r.libc && r.libc.kind, fmtName || r.interp || "static only"].filter(Boolean).join(" ");
  const e = shown(r, "elf.endian"), c = shown(r, "elf.class"), fl = shown(r, "float_abi");
  const detail = [e && e + "-endian", c && c + "-bit", fl && fl !== "unknown" && fl + " float"].filter(Boolean).join(", ");
  return {name, detail};
}

// ---- machine families --------------------------------------------------------
// readelf's Machine text, uname -m and schema 2.3's arch.family all name the
// same thing differently. Unrecognized names become their first word, lowercased,
// which is what the generator puts in arch.family for machines it does not know.
// Same table as FAMILIES in the generator's normalize.py; keep them in sync.
const FAMILIES = [
  [/^(x86[-_]64|amd64|advanced micro devices x86-64)/, "x86_64"],
  [/^(i[3-6]86|x86$|intel 80386)/, "x86"],
  [/^(aarch64|arm64)/, "aarch64"],
  [/^arm/, "arm"],
  [/^mips/, "mips"],
  [/^risc-?v/, "riscv"],
  [/^(ppc|powerpc|power)/, "power"],
  [/^loongarch/, "loongarch"],
  [/^(mc68|m68k|coldfire)/, "m68k"],
  [/^(xilinx microblaze|microblaze)/, "microblaze"],
  [/^(altera nios|nios2)/, "nios2"],
  [/^(openrisc|or1k)/, "openrisc"],
  [/^(ibm s\/390|s390)/, "s390"],
  [/^(renesas \/ superh|superh|sh\d|sh$)/, "sh"],
  [/^sparc/, "sparc"],
  [/^(tensilica xtensa|xtensa)/, "xtensa"],
  [/^(arcv2|arcompact|arc)/, "arc"],
  [/^(analog devices blackfin|blackfin|bfin)/, "blackfin"],
  [/^(c-sky|csky)/, "csky"],
  [/^(tilera tile-gx|tilegx)/, "tilegx"],
  [/^(tilera tilepro|tilepro)/, "tilepro"],
  [/^(intel ia-64|ia64)/, "ia64"],
  [/^alpha/, "alpha"],
  [/^(hppa|parisc)/, "parisc"],                  // readelf says HPPA, uname -m says parisc/parisc64
];
export function machineFamily(name){
  const s = String(name || "").trim().toLowerCase();
  if (!s) return "";
  const hit = FAMILIES.find(([re]) => re.test(s));
  return hit ? hit[1] : s.split(/\s+/)[0];
}
// bFLT records have no ELF Machine and arch.family "unknown"; the triple still names the CPU.
export const recordFamily = r => (r.arch && r.arch.family !== "unknown" && r.arch.family)
  || (r.mips ? "mips" : r.arm ? "arm" : "")
  || machineFamily(r.elf && r.elf.machine) || machineFamily(String(r.triple || "").split("-")[0]);
const recordMachine = r => (r.elf && r.elf.machine) || String(r.triple || "").split("-")[0];
// A 64-bit target that can often run the 32-bit family too (compat kernel + 32-bit libs)
const COMPAT32 = {x86_64: "x86", aarch64: "arm"};
export const elfClass = v => /64/.test(v || "") ? "64" : /32/.test(v || "") ? "32" : "";

// ---- target facts the user can supply -----------------------------------
export const TARGET = [
  {id: "interp",   label: "Loader / interp (readelf -l on a target binary)", ph: "/lib/ld-uClibc.so.0"},
  {id: "provides", label: "Sonames the target provides (ls /lib)",           ph: "libc.so.0, ld-uClibc.so.0"},
  {id: "kernel",   label: "Kernel version (uname -r)",                        ph: "3.18.140"},
  {id: "endian",   label: "Endianness (readelf -h: Data)",                    ph: "big or little"},
  {id: "machine",  label: "Machine (readelf -h: Machine, or uname -m)",       ph: "MIPS R3000"},
  {id: "class",    label: "ELF class (readelf -h: Class)",                    ph: "ELF32 or ELF64"},
  {id: "glibc",    label: "Target glibc version, if glibc",                   ph: "2.19"},
  {id: "format",   label: "Binary format (file on a target binary)",          ph: "ELF, or bFLT on no-MMU uClinux"},
];

// The binary format the target runs: as given, else ELF when a fact only ELF
// targets have (a loader, an ELF class) was given, else "" (unknown).
export function targetFormat(t){
  const f = String(t.format || "");
  if (/bflt|flat/i.test(f)) return "bflt";
  if (/elf/i.test(f)) return "elf";
  return f ? "" : t.interp || t.class ? "elf" : "";
}

// ---- match rules: pure (record, target) -> [{level, text}] --------------
// Each rule only fires when the target facts it needs are present.
// Levels: NO and RISKY set the verdict; INFO is shown but never changes it.
export const vkey = v => (String(v || "").match(/\d+/g) || []).map(Number);
export const vcmp = (a, b) => { const x = vkey(a), y = vkey(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++){ const d = (x[i] || 0) - (y[i] || 0); if (d) return d; } return 0; };

export function provides(t, soname, r){
  if (t.provides.has(soname) || soname === base(t.interp)) return true;
  // musl: libc.so IS the loader; a target with the musl loader satisfies it
  if (r.libc && r.libc.kind === "musl" && soname === "libc.so" && [...t.provides, base(t.interp)].some(s => /^ld-musl-/.test(s))) return true;
  return false;
}
// elf: the rule reads ELF-derived fields, so it only runs on ELF records.
export const RULES = [
  {needs: ["format"], check: (r, t) => {
    const rf = recordFormat(r), tf = targetFormat(t);
    if (rf === "bflt" && tf === "elf")
      return [{level: "NO", text: "binaries are bFLT (uClinux flat, for no-MMU targets); target runs ELF binaries"}];
    if (rf === "elf" && tf === "bflt")
      return [{level: "NO", text: "binaries are ELF; target runs bFLT (uClinux flat) binaries"}];
    return [];
  }},
  {elf: true, needs: ["endian"], check: (r, t) => {
    const e = /little/i.test(t.endian) ? "little" : /big/i.test(t.endian) ? "big" : "";
    return e && r.elf.endian !== e ? [{level: "NO", text: `binaries are ${r.elf.endian}-endian, target is ${e}-endian (exec format error)`}] : [];
  }},
  {needs: ["machine"], check: (r, t) => {
    const rf = recordFamily(r), tf = machineFamily(t.machine);
    if (!rf || !tf || rf === tf) return [];
    if (COMPAT32[tf] === rf)
      return [{level: "RISKY", text: `32-bit ${rf} binaries on a 64-bit ${tf} target: runs only if the kernel has 32-bit support and the 32-bit loader and libs are installed`}];
    return [{level: "NO", text: `binaries are for ${recordMachine(r)} (${rf}), target is ${t.machine} (${tf})`}];
  }},
  {elf: true, needs: ["class"], check: (r, t) => {
    const rc = elfClass(r.elf.class), tc = elfClass(t.class);
    if (!rc || !tc || rc === tc) return [];
    return rc === "64"
      ? [{level: "NO", text: `binaries are ELF64, target userland is ELF32 (no 64-bit loader or libs)`}]
      : [{level: "RISKY", text: `binaries are ELF32, target userland is ELF64: runs only if the target also has the 32-bit loader and libs`}];
  }},
  {elf: true, needs: ["interp"], check: (r, t) =>
    r.interp && r.interp !== t.interp
      ? [{level: "NO", text: `loader is ${r.interp}, target has ${t.interp}`}] : []},
  {elf: true, needs: ["provides"], check: (r, t) =>
    r.needed.filter(n => !provides(t, n, r))
      .map(n => ({level: "NO", text: `needs ${n}, target lacks it`}))},
  {elf: true, needs: ["provides"], check: (r, t) => {
    if (!r.needed_corpus){             // schema 2.0 data: fall back to the loader-soname heuristic
      const l = r.ldso && r.ldso.soname;
      return l && !provides(t, l, r)
        ? [{level: "RISKY", text: `larger or hardened builds can pull in ${l} as NEEDED; target lacks it`}] : [];
    }
    return r.needed_corpus.filter(n => !r.needed.includes(n) && !provides(t, n, r))
      .map(n => ({level: "RISKY", text: `programs using pthreads, select, dlopen or libm also need ${n}; target lacks it`}));
  }},
  {needs: ["kernel"], check: (r, t) => {
    const s = r.time && r.time.time64_syscalls;
    if (s === "required" && vcmp(t.kernel, "5.1") < 0)
      return [{level: "NO", text: `libc uses only the *_time64 syscalls (Linux 5.1+); on ${t.kernel} select, clock_gettime and friends fail with ENOSYS`}];
    if (s === "fallback" && vcmp(t.kernel, "5.1") < 0)
      return [{level: "INFO", text: `libc tries *_time64 syscalls and falls back to the legacy ones on ${t.kernel}`}];
    return [];
  }},
  {needs: ["kernel"], check: (r, t) => {
    const m = r.kernel && r.kernel.min;
    return m && vcmp(t.kernel, m) < 0
      ? [{level: "NO", text: `libc refuses to start below Linux ${m} ("FATAL: kernel too old"); target runs ${t.kernel}`}] : [];
  }},
  {needs: ["kernel"], check: (r, t) => {
    const h = r.kernel && r.kernel.headers;
    return h && vcmp(h, t.kernel) > 0
      ? [{level: "INFO", text: `built against Linux ${h} headers; syscalls newer than ${t.kernel} are unavailable at run time`}] : [];
  }},
  {needs: ["glibc"], check: (r, t) =>
    r.glibc && r.glibc.requires && vcmp(r.glibc.requires, t.glibc) > 0
      ? [{level: "NO", text: `needs GLIBC_${r.glibc.requires} symbols, target glibc is ${t.glibc} ("version not found")`}] : []},
  {elf: true, needs: ["interp"], check: (r, t) =>
    r.hash_style === "gnu" && /uClibc/.test(t.interp)
      ? [{level: "RISKY", text: "binaries only have DT_GNU_HASH; older uClibc loaders only read DT_HASH"}] : []},
];

// The result for a record that is not matched at all, or null.
export function skipResult(r){
  const f = probeFailure(r);
  if (!f) return null;
  const why = f.status === "compile_failed" ? "the compiler ran but compiled nothing, so this record's fields are placeholders"
                                            : `probe status is "${f.status}"`;
  return {verdict: "SKIP", label: f.status.replace(/_/g, " "),
          reasons: [{level: "INFO", text: `not matched: ${why}` + (f.error ? `. Error: ${f.error}` : "")}]};
}

export function matchRecord(r, t){
  const skip = skipResult(r);
  if (skip) return skip;
  t = {...t, format: targetFormat(t)};
  const have = k => k === "provides" ? t.provides.size > 0 : !!t[k];
  const rf = recordFormat(r);
  const wanted = RULES.filter(rule => rule.needs.every(have));
  if (!wanted.length) return null;
  const active = wanted.filter(rule => !rule.elf || rf === "elf");
  const skipped = wanted.length - active.length;
  const rank = {NO: 0, RISKY: 1, INFO: 2};
  // A record that breaks a rule (a field missing or shaped unexpectedly) gets a
  // RISKY reason for that rule instead of breaking the verdicts of every record.
  const run = rule => { try { return rule.check(r, t); }
    catch { return [{level: "RISKY", text: "one check could not run on this record (a field is missing or has an unexpected shape)"}]; } };
  const reasons = active.flatMap(run);
  if (skipped && rf === "bflt")
    reasons.push({level: "INFO", text: "bFLT binaries have no ELF header, loader or NEEDED list; those checks do not apply"});
  else if (skipped)
    reasons.push({level: "RISKY", text: `binary format is "${rf}", not ELF; the ELF checks (endianness, class, loader, libraries) were skipped`});
  reasons.sort((x, y) => rank[x.level] - rank[y.level]);
  const verdict = reasons.some(x => x.level === "NO") ? "NO" : reasons.some(x => x.level === "RISKY") ? "RISKY" : "OK";
  return {verdict, reasons};
}

// ---- dataset contract check ------------------------------------------------
// Returns null if the page can use doc, else the reason it must refuse it.
// Non-blocking: data from a newer 2.x generator may carry fields this page does not show yet.
export function newerDataNote(doc){
  const minor = parseInt(String(doc && doc.schema_version || "").split(".")[1], 10);
  return minor > KNOWN_MINOR
    ? "This data includes some new details this page doesn't use yet. Matching works as usual; the new details are shown as extra columns on the right."
    : null;
}

export function schemaProblem(doc){
  const v = String(doc && doc.schema_version || "");
  if (parseInt(v.split(".")[0], 10) !== SUPPORTED_MAJOR || !Array.isArray(doc.toolchains))
    return `fingerprints.json has schema version "${v || "none"}"; this page only understands ${SUPPORTED_MAJOR}.x. Not showing verdicts that could be wrong.`;
  return null;
}

// ---- parse pasted target output (readelf, ls /lib, uname) into facts --------
// Returns only the facts it found, plus the sonames it saw.
export function parseTargetText(txt){
  const f = {sonames: new Set()};
  const mi = txt.match(/program interpreter:\s*([^\]\s]+)/i);
  if (mi) f.interp = mi[1];
  let m, re = /\[([^\]\s]*\.so[^\]\s]*)\]/g;
  while ((m = re.exec(txt))) f.sonames.add(m[1]);
  re = /(?:^|[\s/])((?:lib|ld)[A-Za-z0-9._+-]*\.so(?:\.[0-9]+)*)/g;
  while ((m = re.exec(txt))) f.sonames.add(m[1]);
  // uname -r / uname -a / /proc/version, or a line that is just a kernel version
  const mk = txt.match(/Linux\s+(?:version\s+|\S+\s+)?(\d+\.\d+(?:\.\d+)?)/) || txt.match(/^\s*(\d+\.\d+\.\d+)\S*\s*$/m);
  if (mk) f.kernel = mk[1];
  const me = txt.match(/Data:.*\b(big|little) endian/i);
  if (me) f.endian = me[1].toLowerCase();
  const mm = txt.match(/^\s*Machine:\s*(.+?)\s*$/m);
  if (mm) f.machine = mm[1];
  const mc = txt.match(/^\s*Class:\s*(ELF(?:32|64))\s*$/m);
  if (mc) f.class = mc[1];
  const mg = txt.match(/\blibc-(\d+\.\d+)\.so\b/) || txt.match(/GNU C Library.*?(\d+\.\d+)/) || txt.match(/^ldd \(.*\)\s+(\d+\.\d+)/m);
  if (mg) f.glibc = mg[1];
  // file(1) says "BFLT executable"; readelf output means the binary is ELF
  if (/\bBFLT executable\b/i.test(txt)) f.format = "bFLT";
  else if (/\bELF (?:32|64)-bit\b|^ELF Header:|^\s*Class:\s*ELF/m.test(txt)) f.format = "ELF";
  return f;
}

