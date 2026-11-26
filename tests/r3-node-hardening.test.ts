import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'
import {
  cloneNullProtoHeaders,
  parseRawHeadersNullProto,
  responseHeadersFromRawHeaders,
} from '../src/server/egress-gateway.ts'
import { redactHeaders, redactJsonValue, redactZdrJsonValue } from '../src/server/redact.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')
const DUNDER_PROTO = `${'__'}proto${'__'}`
const PROD_NODE_FLAGS = [
  '--disable-proto=delete',
  '--enable-experimental-regexp-engine-on-excessive-backtracks',
  '--regexp-backtracks-before-fallback=10000',
]
const THROW_PROTO_NODE_FLAGS = [
  '--disable-proto=throw',
  '--enable-experimental-regexp-engine-on-excessive-backtracks',
  '--regexp-backtracks-before-fallback=10000',
]

function cleanChildEnv(extra: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env }
  delete env.NODE_OPTIONS
  delete env.KOVO_REQUIRE_HARDENED_NODE
  delete env.KOVO_ALLOW_UNHARDENED_NODE_FOR_TEST
  for (const [k, v] of Object.entries(extra)) {
    if (v === undefined) delete env[k]
    else env[k] = v
  }
  return env
}

test('R3-C-1: parseRawHeadersNullProto / responseHeadersFromRawHeaders / cloneNullProtoHeaders build null-proto maps and skip reserved prototype keys', () => {
  const raw = [
    DUNDER_PROTO, 'polluted=1',
    'Constructor', 'evil-ctor',
    'PROTOTYPE', 'evil-proto',
    'Content-Type', 'application/json',
    'Content-Type', 'text/plain',
    'Set-Cookie', 'a=1; HttpOnly',
    'Set-Cookie', 'b=2; Secure',
    'Cookie', 'x=1',
    'Cookie', 'y=2',
    'X-Multi', 'first',
    'x-multi', 'second',
  ]

  const parsed = parseRawHeadersNullProto(raw)
  assert.strictEqual(Object.getPrototypeOf(parsed), null)
  assert.strictEqual(Object.hasOwn(parsed, DUNDER_PROTO), false)
  assert.strictEqual(Object.hasOwn(parsed, 'constructor'), false)
  assert.strictEqual(Object.hasOwn(parsed, 'prototype'), false)
  assert.strictEqual(parsed['content-type'], 'application/json')
  assert.deepStrictEqual(parsed['set-cookie'], ['a=1; HttpOnly', 'b=2; Secure'])
  assert.strictEqual(parsed.cookie, 'x=1; y=2')
  assert.strictEqual(parsed['x-multi'], 'first, second')

  const cloned = cloneNullProtoHeaders(parsed)
  assert.strictEqual(Object.getPrototypeOf(cloned), null)
  assert.deepStrictEqual(cloned['set-cookie'], ['a=1; HttpOnly', 'b=2; Secure'])
  assert.notStrictEqual(cloned['set-cookie'], parsed['set-cookie'])

  const fetchHeaders = responseHeadersFromRawHeaders(raw)
  assert.strictEqual(fetchHeaders.get(DUNDER_PROTO), null)
  assert.strictEqual(fetchHeaders.get('constructor'), null)
  assert.strictEqual(fetchHeaders.get('prototype'), null)
  assert.strictEqual(fetchHeaders.get('x-multi'), 'first, second')
  assert.deepStrictEqual(fetchHeaders.getSetCookie(), ['a=1; HttpOnly', 'b=2; Secure'])
  assert.deepStrictEqual(Object.keys(Object.prototype), [])
})

test('R3-C-1: static guard ensures untrusted HTTP/1 paths in egress-gateway.ts and transport.ts never read IncomingMessage.headers', () => {
  const egressSrc = readFileSync(resolve(REPO_ROOT, 'src/server/egress-gateway.ts'), 'utf8')
  const transportSrc = readFileSync(resolve(REPO_ROOT, 'src/server/transport.ts'), 'utf8')

  assert.doesNotMatch(egressSrc, /\b(?:res|upRes)\.headers\b/, 'egress-gateway.ts must read rawHeaders into null-proto maps instead of IncomingMessage.headers')
  assert.doesNotMatch(transportSrc, /\bres\.headers\b/, 'transport.ts must read rawHeaders into null-proto maps instead of IncomingMessage.headers')
})

test('R3-C-1: raw HTTP/1 server emitting reserved prototype-accessor header never crashes egress-gateway, loopback proxy, broker, or transport (under both --disable-proto=delete and --disable-proto=throw)', () => {
  const probeScript = `
    import assert from 'node:assert/strict';
    import { createServer as createTcpServer } from 'node:net';
    import { request as httpRequest } from 'node:http';
    import { once } from 'node:events';
    import {
      createLoopbackProxy,
      egressFetch,
      egressFetchStream,
      egressRawHttp1,
    } from './src/server/egress-gateway.ts';
    import { createHttpTransport } from './src/server/transport.ts';
    import { RequestBroker } from './src/server/broker.ts';

    const DUNDER = '${DUNDER_PROTO}';
    const bodyText = '{"ok":true,"' + DUNDER + '":{"r3Canary":true},"token":"secret_val_123456"}';
    const rawHttpResponse =
      'HTTP/1.1 200 OK\\r\\n' +
      'Content-Type: application/json\\r\\n' +
      DUNDER + ': r3Canary=1\\r\\n' +
      'Constructor: evil\\r\\n' +
      'Prototype: evil\\r\\n' +
      'X-Safe-Header: intact\\r\\n' +
      'Content-Length: ' + Buffer.byteLength(bodyText) + '\\r\\n' +
      'Connection: close\\r\\n\\r\\n' +
      bodyText;

    // Raw TCP server that sends the reserved prototype-accessor header line on the wire.
    const rawServer = createTcpServer(socket => {
      socket.once('data', () => {
        socket.end(rawHttpResponse);
      });
    });
    rawServer.listen(0, '127.0.0.1');
    await once(rawServer, 'listening');
    const rawPort = rawServer.address().port;
    const origin = 'http://127.0.0.1:' + rawPort;
    const url = new URL(origin + '/probe');

    // Simple HTTP forward proxy server that answers plain-HTTP proxied requests with the same raw response.
    const proxyTargetServer = createTcpServer(socket => {
      socket.once('data', () => {
        socket.end(rawHttpResponse);
      });
    });
    proxyTargetServer.listen(0, '127.0.0.1');
    await once(proxyTargetServer, 'listening');
    const proxyPort = proxyTargetServer.address().port;

    let loopbackProxy;
    try {
      // 1. egressRawHttp1 (readBody: false — default no-body path from R3-C-1)
      const r1NoBody = await egressRawHttp1(url, { address: '127.0.0.1', family: 4 }, { readBody: false });
      assert.strictEqual(r1NoBody.status, 200);
      assert.strictEqual(Object.getPrototypeOf(r1NoBody.headers), null);
      assert.strictEqual(r1NoBody.headers['x-safe-header'], 'intact');
      assert.strictEqual(Object.hasOwn(r1NoBody.headers, DUNDER), false);

      // 2. egressRawHttp1 (readBody: true)
      const r1Body = await egressRawHttp1(url, { address: '127.0.0.1', family: 4 }, { readBody: true });
      assert.strictEqual(r1Body.status, 200);
      assert.strictEqual(Object.getPrototypeOf(r1Body.headers), null);
      assert.strictEqual(r1Body.headers['x-safe-header'], 'intact');
      assert.strictEqual(Object.hasOwn(r1Body.headers, DUNDER), false);
      assert.strictEqual(r1Body.body, bodyText);

      // 3. egressFetch
      const rFetch = await egressFetch(url, {}, { allowLocalLab: true, allowHttp: true });
      assert.strictEqual(rFetch.status, 200);
      assert.strictEqual(rFetch.headers.get('x-safe-header'), 'intact');
      assert.strictEqual(rFetch.headers.get(DUNDER), null);
      assert.strictEqual(await rFetch.text(), bodyText);

      // 4. egressFetchStream
      const rStream = await egressFetchStream(url, {}, { allowLocalLab: true, allowHttp: true });
      assert.strictEqual(rStream.status, 200);
      assert.strictEqual(rStream.headers.get('x-safe-header'), 'intact');
      assert.strictEqual(rStream.headers.get(DUNDER), null);
      assert.strictEqual(await rStream.text(), bodyText);

      // 5. createLoopbackProxy (forward HTTP proxy)
      loopbackProxy = await createLoopbackProxy({ allowLocalLab: true, allowHttp: true });
      const proxyRes = await new Promise((resolveReq, rejectReq) => {
        const req = httpRequest({
          host: loopbackProxy.host,
          port: loopbackProxy.port,
          method: 'GET',
          path: url.href,
          headers: {
            host: url.host,
            'proxy-authorization': loopbackProxy.authorizationHeader,
          },
        }, res => {
          const chunks = [];
          res.on('data', c => chunks.push(c));
          res.on('end', () => resolveReq({
            status: res.statusCode,
            rawHeaders: res.rawHeaders,
            body: Buffer.concat(chunks).toString('utf8'),
          }));
        });
        req.on('error', rejectReq);
        req.end();
      });
      assert.strictEqual(proxyRes.status, 200);
      assert.strictEqual(proxyRes.body, bodyText);
      const loweredProxyHeaderNames = proxyRes.rawHeaders.filter((_, idx) => idx % 2 === 0).map(n => n.toLowerCase());
      assert.strictEqual(loweredProxyHeaderNames.includes(DUNDER), false);
      assert.strictEqual(loweredProxyHeaderNames.includes('x-safe-header'), true);

      // 6. RequestBroker end-to-end against raw TCP socket
      const broker = new RequestBroker({
        resolve: async () => [{ address: '127.0.0.1', family: 4 }],
      });
      const grant = {
        allowLocalLab: true,
        tier: 1,
        canRead: o => { try { return new URL(o).origin === origin } catch { return o === origin } },
        audit: () => undefined,
      };
      const brokerRes = await broker.executeHttp(
        { origin, method: 'GET', pathAndQuery: '/probe' },
        grant,
        new AbortController().signal,
      );
      assert.strictEqual(brokerRes.status, 200);
      assert.strictEqual(brokerRes.respHeaders['x-safe-header'], 'intact');
      assert.strictEqual(Object.hasOwn(brokerRes.respHeaders, DUNDER), false);

      // 7. transport.ts proxyHttp1 (no-body and with-body)
      const transport = createHttpTransport(
        {
          http2: false,
          proxy: { protocol: 'http:', host: '127.0.0.1', port: proxyPort },
        },
        async () => {
          throw new Error('unused fallback')
        },
      );
      const tNoBody = await transport(url, { address: '127.0.0.1', family: 4 }, new AbortController().signal, {
        method: 'GET',
        readBody: false,
      });
      assert.strictEqual(tNoBody.status, 200);
      assert.strictEqual(Object.getPrototypeOf(tNoBody.headers), null);
      assert.strictEqual(tNoBody.headers['x-safe-header'], 'intact');
      assert.strictEqual(Object.hasOwn(tNoBody.headers, DUNDER), false);

      const tBody = await transport(url, { address: '127.0.0.1', family: 4 }, new AbortController().signal, {
        method: 'GET',
        readBody: true,
      });
      assert.strictEqual(tBody.status, 200);
      assert.strictEqual(Object.getPrototypeOf(tBody.headers), null);
      assert.strictEqual(tBody.headers['x-safe-header'], 'intact');
      assert.strictEqual(Object.hasOwn(tBody.headers, DUNDER), false);
      assert.strictEqual(tBody.body, bodyText);
      await transport.close();

      assert.strictEqual(({}).r3Canary, undefined);
      assert.deepStrictEqual(Object.keys(Object.prototype), []);
      console.log(JSON.stringify({ ok: true }));
    } finally {
      await loopbackProxy?.close();
      rawServer.close();
      proxyTargetServer.close();
    }
  `

  for (const [label, flags] of [
    ['production (--disable-proto=delete)', PROD_NODE_FLAGS],
    ['strict (--disable-proto=throw)', THROW_PROTO_NODE_FLAGS],
  ] as const) {
    const out = execFileSync(process.execPath, [...flags, '--input-type=module', '-e', probeScript], {
      cwd: REPO_ROOT,
      env: cleanChildEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }),
      encoding: 'utf8',
      timeout: 20_000,
    })
    assert.deepStrictEqual(JSON.parse(out.trim()), { ok: true }, `expected clean survival under ${label}`)
  }
})

test('R3-C-1: redact.ts safely handles reserved prototype keys in headers and JSON under both --disable-proto=delete and --disable-proto=throw', () => {
  // Direct in-process check
  const untrustedHeaders = JSON.parse(
    `{"${DUNDER_PROTO}":"polluted","constructor":"ctor","Authorization":"Bearer secret_tok_999999","x-ok":"visible"}`,
  ) as Record<string, string>
  const scrubbedHeaders = redactHeaders(untrustedHeaders)
  assert.strictEqual(Object.getPrototypeOf(scrubbedHeaders), null)
  assert.strictEqual(scrubbedHeaders.Authorization, '[redacted]')
  assert.strictEqual(scrubbedHeaders['x-ok'], 'visible')
  assert.strictEqual(Object.keys(Object.prototype).length, 0)

  const untrustedJson = JSON.parse(
    `{"${DUNDER_PROTO}":{"r3Canary":true,"token":"tok_123456789"},"credentials":{"${DUNDER_PROTO}":"nested"},"email":"alice@example.com","ok":"keep"}`,
  ) as Record<string, unknown>
  const scrubbedJson = redactJsonValue(untrustedJson)
  assert.strictEqual(Object.getPrototypeOf(scrubbedJson), null)
  assert.strictEqual(scrubbedJson.ok, 'keep')
  assert.strictEqual(({} as Record<string, unknown>).r3Canary, undefined)

  const scrubbedZdr = redactZdrJsonValue(untrustedJson)
  assert.strictEqual(Object.getPrototypeOf(scrubbedZdr), null)
  assert.strictEqual(scrubbedZdr.email, '[pii:redacted]')
  assert.strictEqual(scrubbedZdr.ok, 'keep')
  assert.strictEqual(({} as Record<string, unknown>).r3Canary, undefined)

  // Subprocess proof under --disable-proto=throw (guarantees zero prototype setter access)
  const script = `
    import assert from 'node:assert/strict';
    import { redactHeaders, redactJsonValue, redactZdrJsonValue } from './src/server/redact.ts';
    const DUNDER = '${DUNDER_PROTO}';
    const hdr = JSON.parse('{"' + DUNDER + '":"x","Authorization":"Bearer secret_abc12345","x-ok":"1"}');
    const outHdr = redactHeaders(hdr);
    assert.strictEqual(Object.getPrototypeOf(outHdr), null);
    assert.strictEqual(outHdr.Authorization, '[redacted]');
    assert.strictEqual(outHdr['x-ok'], '1');

    const payload = JSON.parse('{"' + DUNDER + '":{"r3Canary":true},"credentials":{"' + DUNDER + '":"s"},"email":"a@b.co","ok":"v"}');
    const outJson = redactJsonValue(payload);
    const outZdr = redactZdrJsonValue(payload);
    assert.strictEqual(Object.getPrototypeOf(outJson), null);
    assert.strictEqual(Object.getPrototypeOf(outZdr), null);
    assert.strictEqual(outZdr.email, '[pii:redacted]');
    assert.strictEqual(({}).r3Canary, undefined);
    console.log(JSON.stringify({ ok: true }));
  `
  for (const flags of [PROD_NODE_FLAGS, THROW_PROTO_NODE_FLAGS]) {
    const out = execFileSync(process.execPath, [...flags, '--input-type=module', '-e', script], {
      cwd: REPO_ROOT,
      env: cleanChildEnv(),
      encoding: 'utf8',
      timeout: 15_000,
    })
    assert.deepStrictEqual(JSON.parse(out.trim()), { ok: true })
  }
})

test('R3-C-1: installHostUncaughtExceptionGuard logs structured JSON, survives isolated errors, and fails fast on unrecoverable errors or storms', () => {
  const script = `
    import assert from 'node:assert/strict';
    import { installHostUncaughtExceptionGuard } from './scripts/serve.ts';

    const logs = [];
    const fatals = [];
    let fakeNow = 1_000_000;
    const uninstall = installHostUncaughtExceptionGuard({
      logError: line => logs.push(JSON.parse(line)),
      onFatal: (err, _origin, reason) => fatals.push({ code: err?.code ?? null, reason }),
      now: () => fakeNow,
      stormLimit: 3,
      stormWindowMs: 5_000,
    });

    // 1. Real asynchronous uncaughtException is intercepted, logged as structured JSON, and does NOT crash the process.
    await new Promise(resolve => {
      setImmediate(() => {
        const err = Object.assign(new Error('isolated socket parse fault'), { code: 'HPE_INVALID_HEADER_TOKEN' });
        throw err;
      });
      setTimeout(resolve, 40);
    });
    assert.strictEqual(logs.length, 1);
    assert.strictEqual(logs[0].event, 'host.uncaught_exception');
    assert.strictEqual(logs[0].fatal, false);
    assert.strictEqual(logs[0].code, 'HPE_INVALID_HEADER_TOKEN');
    assert.strictEqual(fatals.length, 0);

    // 2. Storm of 3 errors within stormWindowMs trips fatal shutdown.
    fakeNow += 500;
    process.emit('uncaughtException', new Error('second error'), 'uncaughtException');
    assert.strictEqual(fatals.length, 0);
    fakeNow += 500;
    process.emit('uncaughtException', new Error('third error'), 'uncaughtException');
    assert.strictEqual(fatals.length, 1);
    assert.match(fatals[0].reason, /^uncaught_exception_storm/);
    assert.strictEqual(logs[2].fatal, true);
    uninstall();

    // 3. Unrecoverable OOM error triggers fatal immediately on first event.
    const oomFatals = [];
    const uninstallOom = installHostUncaughtExceptionGuard({
      logError: () => undefined,
      onFatal: (_err, _origin, reason) => oomFatals.push(reason),
    });
    const oom = Object.assign(new Error('heap exhausted'), { code: 'ERR_OUT_OF_MEMORY' });
    process.emit('uncaughtException', oom, 'uncaughtException');
    assert.deepStrictEqual(oomFatals, ['unrecoverable_runtime_error']);
    uninstallOom();

    console.log(JSON.stringify({ ok: true }));
  `

  const out = execFileSync(process.execPath, [...PROD_NODE_FLAGS, '--input-type=module', '-e', script], {
    cwd: REPO_ROOT,
    env: cleanChildEnv(),
    encoding: 'utf8',
    timeout: 15_000,
  })
  assert.deepStrictEqual(JSON.parse(out.trim()), { ok: true })
})

test('R3-H-11: package.json and Dockerfile enforce hardened Node flags and startup fails closed without linear-regexp fallback', () => {
  const pkg = JSON.parse(readFileSync(resolve(REPO_ROOT, 'package.json'), 'utf8')) as {
    scripts: Record<string, string>
  }
  for (const scriptName of ['start', 'scan'] as const) {
    const cmd = pkg.scripts[scriptName] ?? ''
    assert.match(cmd, /--disable-proto=delete/, `package.json scripts.${scriptName} must pass --disable-proto=delete`)
    assert.doesNotMatch(cmd, /--disable-proto=throw/, `package.json scripts.${scriptName} must not use --disable-proto=throw`)
    assert.match(
      cmd,
      /--enable-experimental-regexp-engine-on-excessive-backtracks/,
      `package.json scripts.${scriptName} must pass --enable-experimental-regexp-engine-on-excessive-backtracks`,
    )
    assert.match(
      cmd,
      /--regexp-backtracks-before-fallback=10000/,
      `package.json scripts.${scriptName} must pass --regexp-backtracks-before-fallback=10000`,
    )
  }

  const dockerfile = readFileSync(resolve(REPO_ROOT, 'Dockerfile'), 'utf8')
  assert.match(dockerfile, /--disable-proto=delete/)
  assert.doesNotMatch(dockerfile, /--disable-proto=throw/)
  assert.match(dockerfile, /--enable-experimental-regexp-engine-on-excessive-backtracks/)
  assert.match(dockerfile, /--regexp-backtracks-before-fallback=10000/)

  // 1. hardenHostProcess() and hardenCliProcess() fail closed when linear-regexp flag is absent.
  const unhardenedCheck = `
    import { hardenHostProcess } from './scripts/serve.ts';
    import { hardenCliProcess } from './scripts/cli.ts';
    const results = {};
    for (const [name, fn] of [['host', hardenHostProcess], ['cli', hardenCliProcess]]) {
      try {
        fn({ quiet: true });
        results[name] = { threw: false };
      } catch (err) {
        results[name] = { threw: true, message: err instanceof Error ? err.message : String(err) };
      }
    }
    console.log(JSON.stringify(results));
  `
  const unhardenedOut = execFileSync(process.execPath, ['--input-type=module', '-e', unhardenedCheck], {
    cwd: REPO_ROOT,
    env: cleanChildEnv(),
    encoding: 'utf8',
    timeout: 15_000,
  })
  const unhardenedParsed = JSON.parse(unhardenedOut.trim()) as {
    host: { threw: boolean; message?: string }
    cli: { threw: boolean; message?: string }
  }
  assert.strictEqual(unhardenedParsed.host.threw, true, 'hardenHostProcess must fail closed without linear-regexp flag')
  assert.match(unhardenedParsed.host.message ?? '', /--enable-experimental-regexp-engine-on-excessive-backtracks/)
  assert.strictEqual(unhardenedParsed.cli.threw, true, 'hardenCliProcess must fail closed without linear-regexp flag')
  assert.match(unhardenedParsed.cli.message ?? '', /--enable-experimental-regexp-engine-on-excessive-backtracks/)

  // 2. Direct invocation of scripts/cli.ts and scripts/serve.ts without linear-regexp flag fails fast (exit != 0).
  const cliNoFlag = spawnSync(process.execPath, ['scripts/cli.ts', '--help'], {
    cwd: REPO_ROOT,
    env: cleanChildEnv(),
    encoding: 'utf8',
    timeout: 15_000,
  })
  assert.notStrictEqual(cliNoFlag.status, 0, 'scripts/cli.ts must exit non-zero without linear-regexp flag')
  assert.match(cliNoFlag.stderr, /--enable-experimental-regexp-engine-on-excessive-backtracks/)

  const serveNoFlag = spawnSync(process.execPath, ['scripts/serve.ts'], {
    cwd: REPO_ROOT,
    env: cleanChildEnv(),
    encoding: 'utf8',
    timeout: 15_000,
  })
  assert.notStrictEqual(serveNoFlag.status, 0, 'scripts/serve.ts must exit non-zero without linear-regexp flag')
  assert.match(serveNoFlag.stderr, /--enable-experimental-regexp-engine-on-excessive-backtracks/)

  // 3. Explicit test opt-out env allows unflagged startup when KOVO_REQUIRE_HARDENED_NODE is unset,
  //    but KOVO_REQUIRE_HARDENED_NODE=1 still fails closed even if opt-out env is set.
  const optOutOut = execFileSync(process.execPath, ['--input-type=module', '-e', unhardenedCheck], {
    cwd: REPO_ROOT,
    env: cleanChildEnv({ KOVO_ALLOW_UNHARDENED_NODE_FOR_TEST: '1' }),
    encoding: 'utf8',
    timeout: 15_000,
  })
  const optOutParsed = JSON.parse(optOutOut.trim()) as {
    host: { threw: boolean }
    cli: { threw: boolean }
  }
  assert.strictEqual(optOutParsed.host.threw, false)
  assert.strictEqual(optOutParsed.cli.threw, false)

  const strictOverrideOut = execFileSync(process.execPath, ['--input-type=module', '-e', unhardenedCheck], {
    cwd: REPO_ROOT,
    env: cleanChildEnv({ KOVO_REQUIRE_HARDENED_NODE: '1', KOVO_ALLOW_UNHARDENED_NODE_FOR_TEST: '1' }),
    encoding: 'utf8',
    timeout: 15_000,
  })
  const strictOverrideParsed = JSON.parse(strictOverrideOut.trim()) as {
    host: { threw: boolean }
    cli: { threw: boolean }
  }
  assert.strictEqual(strictOverrideParsed.host.threw, true)
  assert.strictEqual(strictOverrideParsed.cli.threw, true)

  // 4. Hardened flags pass both startup checks and CLI execution cleanly.
  const hardenedCheck = `
    import { hardenHostProcess } from './scripts/serve.ts';
    import { hardenCliProcess } from './scripts/cli.ts';
    console.log(JSON.stringify({
      host: hardenHostProcess({ quiet: true }),
      cli: hardenCliProcess({ quiet: true }),
    }));
  `
  const hardenedOut = execFileSync(process.execPath, [...PROD_NODE_FLAGS, '--input-type=module', '-e', hardenedCheck], {
    cwd: REPO_ROOT,
    env: cleanChildEnv(),
    encoding: 'utf8',
    timeout: 15_000,
  })
  const hardenedParsed = JSON.parse(hardenedOut.trim()) as {
    host: { linearRegexpFallback: boolean; disableProtoDelete: boolean; warnings: string[] }
    cli: { linearRegexpFallback: boolean; disableProtoDelete: boolean; warnings: string[] }
  }
  assert.strictEqual(hardenedParsed.host.linearRegexpFallback, true)
  assert.strictEqual(hardenedParsed.host.disableProtoDelete, true)
  assert.deepStrictEqual(hardenedParsed.host.warnings, [])
  assert.strictEqual(hardenedParsed.cli.linearRegexpFallback, true)
  assert.strictEqual(hardenedParsed.cli.disableProtoDelete, true)
  assert.deepStrictEqual(hardenedParsed.cli.warnings, [])

  const cliWithFlags = spawnSync(process.execPath, [...PROD_NODE_FLAGS, 'scripts/cli.ts', '--help'], {
    cwd: REPO_ROOT,
    env: cleanChildEnv(),
    encoding: 'utf8',
    timeout: 15_000,
  })
  assert.strictEqual(cliWithFlags.status, 0)
  assert.match(cliWithFlags.stdout, /Kovo Hunter Headless Security Scanner CLI/)
})
