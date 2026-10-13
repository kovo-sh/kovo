import {build} from "esbuild";
import {createHash} from "node:crypto";
import {chmodSync,readFileSync,writeFileSync} from "node:fs";
const options = {
  "bundle": true,
  "platform": "node",
  "format": "esm",
  "target": "node22",
  "conditions": [
    "@kovo/source"
  ],
  "banner": {
    "js": "import { createRequire as __kovoCreateRequire } from \"node:module\"; const require = __kovoCreateRequire(import.meta.url);"
  },
  "legalComments": "eof",
  "charset": "utf8",
  "logLevel": "warning",
  "write": false,
  "metafile": true
}
;
const aliases = {
  "@kovo/contracts": "packages/contracts/src/index.ts",
  "@kovo/contracts/api": "packages/contracts/src/api/index.ts",
  "@kovo/contracts/redaction": "packages/contracts/src/redaction/index.ts",
  "@kovo/adapters/osv": "packages/adapters/src/osv/index.ts",
  "@kovo/core/advisory": "packages/core/src/advisory/index.ts",
  "@kovo/adapters/npm/packument": "packages/adapters/src/npm/packument.ts",
  "@kovo/core/dependency-verdicts": "packages/core/src/dependency-verdicts/index.ts",
  "@kovo/core/lockfile": "packages/core/src/lockfile/index.ts",
  "@kovo/core/manifest": "packages/core/src/manifest/index.ts"
}
;
await build({...options, absWorkingDir: process.cwd(), entryPoints: ["packages/cli/src/bin/kovo.ts"], alias: Object.fromEntries(Object.entries(aliases).map(([key,path])=>[key, "./"+path])), outfile:"dist/kovo.js", write:true});
chmodSync("dist/kovo.js",0o755);
writeFileSync("dist/kovo.js.sha256",createHash("sha256").update(readFileSync("dist/kovo.js")).digest("hex")+"  kovo.js\n");
