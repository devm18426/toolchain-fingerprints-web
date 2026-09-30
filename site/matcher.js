// Pure matcher logic: no DOM. Imported by index.html and by the tests.
// ---- contract ------------------------------------------------------------
export const SUPPORTED_MAJOR = 2;           // refuse any other major version of the schema
export const KNOWN_MINOR = 3;               // newest 2.x this page was written against
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
  ["tc_id", "toolchain"], ["triple", "triple", "mono"], ["libc.kind", "libc"],
  ["libc.version", "libc ver"], ["gcc_version", "gcc"],
  ["elf.machine", "machine"], ["elf.class", "class"], ["elf.endian", "endian"], ["march", "-march"], ["isa", "isa"],
  ["float_abi", "float"], [archFamily, "arch"], [archAbi, "arch ABI"],
  ["time.time_t_bits", "time_t bits"], ["time.time64_syscalls", "time64 syscalls"],
  ["kernel.headers", "kernel headers"], ["kernel.min", "min kernel"],
  ["glibc.requires", "needs GLIBC_"], ["glibc.provides", "has GLIBC_"],
  ["pie_default", "PIE"], ["hash_style", "hash"], ["interp", "interp", "mono"],
  ["needed", "needed (hello)", "mono"], ["needed_corpus", "needed (real programs)", "mono"],
  ["ldso.soname", "ldso soname", "mono"], ["libc.soname", "libc soname", "mono"],
  ["dynamic_ok", "dynamic"], ["static_ok", "static"], ["cxx_ok", "C++"],
  ["sysroot_sonames", "sysroot sonames", "mono list"],
];

// Field paths the curated columns already cover (whole subtrees for prefixes),
// plus subtrees that are never shown as columns.
const COVERED = ["arch", "mips", "arm", "raw", "provenance"];

// Leaf fields in the data that no column covers, e.g. fields added by a newer
// 2.x generator. Returned in COLS shape so the page can append them to the table.
export function extraCols(records){
  const known = new Set(COLS.map(c => c[0]).filter(k => typeof k === "string"));
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
function archFamily(r){ return r.arch ? r.arch.family : r.mips ? "mips" : r.arm ? "arm" : ""; }
function archAbi(r){ return r.arch ? r.arch.abi : r.mips || r.arm || null; }
export const cell = (r, key) => typeof key === "function" ? key(r) : get(r, key);

// ---- machine families --------------------------------------------------------
// readelf's Machine text, uname -m and schema 2.3's arch.family all name the
// same thing differently. Unrecognized names become their first word, lowercased,
// which is what the generator puts in arch.family for machines it does not know.
const FAMILIES = [
  [/^(x86[-_]64|amd64|advanced micro devices x86-64)/, "x86_64"],
  [/^(i[3-6]86|x86$|intel 80386)/, "x86"],
  [/^(aarch64|arm64)/, "aarch64"],
  [/^arm/, "arm"],
  [/^mips/, "mips"],
  [/^risc-?v/, "riscv"],
  [/^(ppc|powerpc|power)/, "power"],
  [/^loongarch/, "loongarch"],
];
export function machineFamily(name){
  const s = String(name || "").trim().toLowerCase();
  if (!s) return "";
  const hit = FAMILIES.find(([re]) => re.test(s));
  return hit ? hit[1] : s.split(/\s+/)[0];
}
export const recordFamily = r => (r.arch && r.arch.family) || machineFamily(r.elf && r.elf.machine);
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
];

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
export const RULES = [
  {needs: ["endian"], check: (r, t) => {
    const e = /little/i.test(t.endian) ? "little" : /big/i.test(t.endian) ? "big" : "";
    return e && r.elf.endian !== e ? [{level: "NO", text: `binaries are ${r.elf.endian}-endian, target is ${e}-endian (exec format error)`}] : [];
  }},
  {needs: ["machine"], check: (r, t) => {
    const rf = recordFamily(r), tf = machineFamily(t.machine);
    if (!rf || !tf || rf === tf) return [];
    if (COMPAT32[tf] === rf)
      return [{level: "RISKY", text: `32-bit ${rf} binaries on a 64-bit ${tf} target: runs only if the kernel has 32-bit support and the 32-bit loader and libs are installed`}];
    return [{level: "NO", text: `binaries are for ${r.elf.machine} (${rf}), target is ${t.machine} (${tf})`}];
  }},
  {needs: ["class"], check: (r, t) => {
    const rc = elfClass(r.elf.class), tc = elfClass(t.class);
    if (!rc || !tc || rc === tc) return [];
    return rc === "64"
      ? [{level: "NO", text: `binaries are ELF64, target userland is ELF32 (no 64-bit loader or libs)`}]
      : [{level: "RISKY", text: `binaries are ELF32, target userland is ELF64: runs only if the target also has the 32-bit loader and libs`}];
  }},
  {needs: ["interp"], check: (r, t) =>
    r.interp && r.interp !== t.interp
      ? [{level: "NO", text: `loader is ${r.interp}, target has ${t.interp}`}] : []},
  {needs: ["provides"], check: (r, t) =>
    r.needed.filter(n => !provides(t, n, r))
      .map(n => ({level: "NO", text: `needs ${n}, target lacks it`}))},
  {needs: ["provides"], check: (r, t) => {
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
  {needs: ["interp"], check: (r, t) =>
    r.hash_style === "gnu" && /uClibc/.test(t.interp)
      ? [{level: "RISKY", text: "binaries only have DT_GNU_HASH; older uClibc loaders only read DT_HASH"}] : []},
];

export function matchRecord(r, t){
  const have = k => k === "provides" ? t.provides.size > 0 : !!t[k];
  const active = RULES.filter(rule => rule.needs.every(have));
  if (!active.length) return null;
  const rank = {NO: 0, RISKY: 1, INFO: 2};
  // A record that breaks a rule (a field missing or shaped unexpectedly) gets a
  // RISKY reason for that rule instead of breaking the verdicts of every record.
  const run = rule => { try { return rule.check(r, t); }
    catch { return [{level: "RISKY", text: "one check could not run on this record (a field is missing or has an unexpected shape)"}]; } };
  const reasons = active.flatMap(run).sort((x, y) => rank[x.level] - rank[y.level]);
  const verdict = reasons.some(x => x.level === "NO") ? "NO" : reasons.some(x => x.level === "RISKY") ? "RISKY" : "OK";
  return {verdict, reasons};
}

// ---- dataset contract check ------------------------------------------------
// Returns null if the page can use doc, else the reason it must refuse it.
// Non-blocking: data from a newer 2.x generator may carry fields this page does not show yet.
export function newerDataNote(doc){
  const minor = parseInt(String(doc && doc.schema_version || "").split(".")[1], 10);
  return minor > KNOWN_MINOR
    ? `This dataset is schema ${doc.schema_version}, newer than this page (${SUPPORTED_MAJOR}.${KNOWN_MINOR}). Verdicts are still valid; fields this page does not know yet are shown as extra columns at the right, and no rule uses them.`
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
  return f;
}

