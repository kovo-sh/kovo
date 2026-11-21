# Unsafe Deserialization: Safe Fingerprinting & Static Audit
Tags: deserialization, serialization, pickle, yaml, jackson, java, python, php, ruby, static-analysis
Summary: Audit binary and polymorphic deserialization boundaries statically via offline SAST and passive response/cookie fingerprinting without sending destructive gadget chains.

## 1. Strictly Defensive Boundary
Guardian strictly prohibits sending weaponized gadget chains, arbitrary code-execution serialized objects, or destructive deserialization payloads. Deserialization risks MUST be audited primarily through source code (`/repos`), dependency inventory (`query_cves`), and strictly passive format fingerprinting.

## 2. Source-First Deserialization Audit (`/repos`)
Run `run_sast_scan` (`opengrep`, `ast-grep`, `bandit`, `trivy-fs`) and search `/repos` via `derive_evidence` for unsafe deserializers reachable from HTTP bodies, cookies, headers, message queues, or caches:
1. **Python:** Flag `pickle.loads`, `cPickle`, `marshal.loads`, `shelve`, `dill`, `jsonpickle.decode`, or `yaml.load(..., Loader=yaml.Loader/UnsafeLoader)` instead of `json.loads` or `yaml.safe_load`.
2. **Java / JVM:** Flag `ObjectInputStream.readObject()`, `XMLDecoder`, `XStream` without an explicit type allowlist (`allowTypes`), Kryo without registration required, or Jackson `enableDefaultTyping()` / `activateDefaultTyping(LaissezFaireSubTypeValidator.instance)`.
3. **Node.js / JavaScript:** Flag `node-serialize`, `serialize-javascript` evaluated on untrusted input, or `js-yaml` legacy `load` with unsafe schema tags.
4. **Ruby / PHP / .NET:** Flag Ruby `Marshal.load` / `YAML.load`, PHP `unserialize()` on untrusted input (without `['allowed_classes' => false]`), and .NET `BinaryFormatter`, `LosFormatter`, `SoapFormatter`, or `Newtonsoft.Json` with `TypeNameHandling != None`.

## 3. Passive Runtime Fingerprinting (Tier 1–2 Read-Only)
When source is unavailable, inspect captured HTTP exchanges (`search_exchanges`, `analyze_artifact`, `run_offline_script`):
- Identify serialized container formats passively in cookies, hidden form fields, view-state tokens, or API parameters (e.g., Base64-encoded headers, unsigned state blobs, Java/PHP/Python serialization magic prefixes, or missing HMAC/AEAD integrity wrappers).
- Verify whether the endpoint signs and verifies state blobs with a server-side HMAC or authenticated encryption before decoding. Never transmit active gadget payloads.

## 4. Closure & Remediation
- **Remediation:** Replace native object serialization with data-only formats (JSON with strict schema validation such as Zod/Pydantic/Jackson DTOs). If serialized tokens must cross trust boundaries, enforce HMAC-SHA256/AEAD verification BEFORE deserialization and pin strict class allowlists.
- **Closure:** Submit verified unguarded source sinks as `static_ast_proof` (`static_verified` tier) with exact `file:line`, `runtimeProofGap`, and `counterevidence` (checking whether an HMAC signature or upstream allowlist guards the deserializer). Close safe JSON/HMAC-verified paths via `record_coverage` (`status: "ruled_out"`, `enforcingControl: "<file:line>"`).
