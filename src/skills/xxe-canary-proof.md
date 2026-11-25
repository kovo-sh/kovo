# XML Parser Hardening & Benign Canary Verification (XXE Audit)
Tags: xxe, xml, parser, dtd, soap, svg, docx, canary, oob, static-analysis
Summary: Audit XML, SOAP, SAML, RSS, SVG, and office-document parsers offline for unsafe DTD/external-entity defaults and verify outbound resolution strictly with Kovo Hunter’s signed HTTP/DNS CanaryBroker.

## 1. Strictly Defensive Boundary
Kovo Hunter strictly prohibits reading local host files, probing RFC1918/internal services or cloud metadata addresses, or sending entity-expansion denial-of-service documents ("billion laughs"). All runtime XXE verification MUST use ONLY Kovo Hunter’s self-hosted signed `CanaryBroker` HTTP/DNS callbacks—never local file paths and never third-party OAST services.

## 2. Source-First XML Parser Audit (`/repos`)
Run `run_sast_scan` (`opengrep`, `ast-grep`, `bandit`) and inspect XML/SVG/SAML/Office parsing libraries in `/repos`:
1. **Java / JVM (`DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `SchemaFactory`, `JAXB`):**
   - Verify `disallow-doctype-decl` is set to `true` (preferred) OR both `external-general-entities` and `external-parameter-entities` are disabled AND `load-external-dtd` is `false` with `XMLConstants.FEATURE_SECURE_PROCESSING` enabled.
2. **Python (`xml.etree`, `lxml`, `minidom`, `xml.sax`):**
   - Prefer `defusedxml`. On `lxml.etree.XMLParser`, verify `resolve_entities=False`, `no_network=True`, and `load_dtd=False`.
3. **Node.js / PHP / .NET:**
   - Flag Node `libxmljs` with `noent: true` or `dtdload: true` (prefer `fast-xml-parser` or `xml2js` with DTD disabled).
   - Flag PHP `LIBXML_NOENT` / `LIBXML_DTDLOAD` or missing safe loader defaults; flag .NET `XmlDocument`/`XmlTextReader` with non-null `XmlResolver` or `DtdProcessing.Parse`.
4. **Hidden XML Entry Points:** Remember endpoints accepting `application/xml`, `text/xml`, `image/svg+xml` uploads, SAML assertions, SOAP actions, RSS/Atom feeds, or zipped XML formats (DOCX/XLSX/PPTX/ODT) and JSON endpoints whose middleware also parses XML when `Content-Type: application/xml` is sent.

## 3. Safe Non-Destructive Runtime Verification
- Mint a single-use Kovo Hunter canary via `mint_canary` (using Kovo Hunter’s self-hosted HTTP callback URL or authoritative DNS hostname when configured).
- Compare a clean valid XML baseline control against a benign external-DTD canary reference check strictly within approved scope (Tier 2/3 as appropriate for `POST` / `upload_probe`), then poll `check_canary` for an authoritative callback correlated to the minted token.
- Never request local files or internal IPs; confirm strictly via out-of-band Kovo Hunter canary hit (`rce_proof` `oob_canary` or `http_chain`) or static AST proof (`static_ast_proof` -> `static_verified`).

## 4. Closure & Remediation
- **Remediation:** Disable DTD processing completely (`disallow-doctype-decl = true` / `defusedxml` / `resolve_entities=False, no_network=True`) on every XML parser across the repository.
- **Closure:** Record `ruled_out` only by quoting the exact parser hardening configuration `file:line` or negative-control `exchangeId` in `enforcingControl`.
