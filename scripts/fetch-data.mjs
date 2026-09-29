#!/usr/bin/env node
// Put the dataset pinned in data.lock next to the page, after checking it.
//
//   node scripts/fetch-data.mjs                download data.lock's release asset, verify sha256
//   node scripts/fetch-data.mjs --update TAG   pin data.lock to release TAG (records its sha256)
//   node scripts/fetch-data.mjs --from FILE    use a local fingerprints.json (development only)
//
// Writes site/fingerprints.json and site/data-release.json. Refuses a dataset
// whose schema major version the page does not support.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { schemaProblem } from "../site/matcher.js";

const root = fileURLToPath(new URL("..", import.meta.url));
const lockPath = root + "data.lock";
const die = msg => { console.error(`fetch-data: ${msg}`); process.exit(1); };
const sha256 = buf => createHash("sha256").update(buf).digest("hex");

async function download(repo, tag){
  const url = `https://github.com/${repo}/releases/download/${tag}/fingerprints.json`;
  const res = await fetch(url);
  if (!res.ok) die(`${url}: HTTP ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

const args = process.argv.slice(2);
const lock = JSON.parse(readFileSync(lockPath, "utf8"));
let buf, release;

if (args[0] === "--from"){
  if (!args[1]) die("--from needs a file");
  buf = readFileSync(args[1]);
  release = {repo: lock.repo, tag: `local:${args[1]}`, sha256: sha256(buf)};
} else if (args[0] === "--update"){
  const tag = args[1];
  if (!/^data-[0-9]+\.[0-9]+\.[0-9]+$/.test(tag || "")) die(`--update needs a release tag like data-2.2.1, got ${tag}`);
  buf = await download(lock.repo, tag);
  release = {repo: lock.repo, tag, sha256: sha256(buf)};
  writeFileSync(lockPath, JSON.stringify(release, null, 2) + "\n");
  console.log(`pinned data.lock to ${tag} (${release.sha256})`);
} else {
  if (!lock.tag) die("data.lock has no release pinned yet; run with --update TAG (or --from FILE locally)");
  buf = await download(lock.repo, lock.tag);
  if (sha256(buf) !== lock.sha256) die(`sha256 mismatch for ${lock.tag}: got ${sha256(buf)}, data.lock says ${lock.sha256}`);
  release = lock;
}

let doc;
try { doc = JSON.parse(buf.toString("utf8")); } catch (e){ die(`not JSON: ${e.message}`); }
const problem = schemaProblem(doc);
if (problem) die(problem);

writeFileSync(root + "site/fingerprints.json", buf);
writeFileSync(root + "site/data-release.json", JSON.stringify(release, null, 2) + "\n");
console.log(`site/fingerprints.json: ${doc.toolchains.length} toolchains, schema ${doc.schema_version}, from ${release.tag}`);
