"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

function writeU32(bytes, offset, value) {
  new DataView(bytes.buffer).setUint32(offset, value, true);
}

function makeModule(name, filePath, cryptsize, cryptid, options = {}) {
  const bytes = new Uint8Array(Math.max(512, 128 + cryptsize));
  const uuid = options.uuid;
  for (const [offset, value] of [
    [0, options.magic ?? 0xfeedfacf], [4, options.cputype ?? 0x0100000c], [8, options.cpusubtype ?? 0],
    [16, options.ncmds ?? (uuid ? 2 : 1)],
    [32, 0x2c], [36, options.cmdsize ?? 24], [40, 128], [44, cryptsize], [48, cryptid],
  ]) writeU32(bytes, offset, value);
  if (uuid) {
    writeU32(bytes, 56, 0x1b);
    writeU32(bytes, 60, 24);
    bytes.set(uuid, 64);
  }
  bytes.fill(0x7f, 128, 128 + cryptsize);

  const pointer = (offset = 0) => ({
    add: (amount) => pointer(offset + amount),
    readU32: () => new DataView(bytes.buffer).getUint32(offset, true),
    readByteArray: (length) => bytes.slice(offset, offset + length).buffer,
  });
  return { name, path: filePath, base: pointer(), size: bytes.length };
}

function loadAgent(modules, options = {}) {
  const messages = [];
  const runtime = {
    Process: {
      mainModule: options.mainModule === undefined ? modules[0] : options.mainModule,
      enumerateModules: options.enumerateModules ?? (() => modules),
    },
    Module: options.module ?? { getGlobalExportByName: () => null },
    Interceptor: { attach: (address, callbacks) => options.attach?.(address, callbacks) },
    rpc: { exports: {} },
    send: (payload, data) => messages.push({ payload, data }),
  };

  const source = fs.readFileSync(path.join(__dirname, "ipakeep_dump.js"), "utf8");
  vm.runInNewContext(source, runtime, { filename: path.join(__dirname, "ipakeep_dump.js") });
  return { runtime, messages };
}

function testDecryptedDylibsAreDumped() {
  const root = "/Applications/Test.app/";
  const main = makeModule("Test", path.join(root, "Test"), 0, 0);
  const uuid = Uint8Array.from({ length: 16 }, (_, index) => index);
  const dylib = makeModule("Framework", path.join(root, "Frameworks/Framework"), 32, 0, { uuid });
  const { runtime, messages } = loadAgent([main, dylib]);
  runtime.rpc.exports.arm();

  const slice = messages.find(({ payload }) => payload.name === "Frameworks%2FFramework.arm64.bin");
  assert.equal(slice.payload.name, "Frameworks%2FFramework.arm64.bin");
  assert.equal(slice.payload.cryptsize, 32);
  assert.deepEqual([...new Uint8Array(slice.data)], Array(32).fill(0x7f));
  const sidecar = messages.find(({ payload }) => payload.name?.endsWith(".uuid"));
  assert.equal(sidecar.payload.name, "Frameworks%2FFramework.arm64.bin.uuid");
  assert.equal(Buffer.from(sidecar.data).toString(), "000102030405060708090A0B0C0D0E0F");
}

function testArchitecturesBundleFallbackAndLargeRegions() {
  const root = "/Applications/Test.app/";
  const main = makeModule("Test", path.join(root, "Test"), 0, 0);
  const x86 = makeModule("X", path.join(root, "X"), 1, 0, { cputype: 0x01000007 });
  const arm64e = makeModule("E", path.join(root, "E"), 1, 0, { cpusubtype: 2 });
  const unknown = makeModule("U", path.join(root, "U"), 1, 0, { cputype: 0x1234 });
  const large = makeModule("Large", path.join(root, "Large"), 16 * 1024 * 1024 + 1, 0);
  const { runtime, messages } = loadAgent([main, x86, arm64e, unknown, large], { mainModule: null });
  assert.equal(runtime.rpc.exports.arm(), root);
  assert(messages.some(({ payload }) => payload.name === "X.x86_64.bin"));
  assert(messages.some(({ payload }) => payload.name === "E.arm64e.bin"));
  assert(messages.some(({ payload }) => payload.name === "U.cpu-1234.bin"));
  const chunks = messages.filter(({ payload }) => payload.name?.startsWith("Large.arm64.bin.part."));
  assert.equal(chunks.length, 2);
  assert.equal(chunks[0].payload.cryptsize, 16 * 1024 * 1024);
  assert.equal(chunks[1].payload.cryptsize, 1);
  assert.equal(chunks[1].payload.total, 16 * 1024 * 1024 + 1);
}

function testSweepDeduplicatesAndSkipsBadModulesAndOutsideBundle() {
  const root = "/Applications/Test.app/";
  const main = makeModule("Test", path.join(root, "Test"), 0, 0);
  const framework = makeModule("Framework", path.join(root, "Frameworks/F"), 4, 0);
  const broken = { path: path.join(root, "Broken"), base: { readU32: () => { throw new Error("bad header"); } } };
  const system = makeModule("System", "/System/Library/System", 4, 0);
  const { runtime, messages } = loadAgent([main, framework, broken, system]);
  runtime.rpc.exports.arm();
  runtime.rpc.exports.sweep();
  assert.equal(messages.filter(({ payload }) => payload.name === "Frameworks%2FF.arm64.bin").length, 1);
  assert.equal(messages.at(-1).payload.event, "done");
  assert.equal(messages.at(-1).payload.dumped, 1);
}

function testDlopenHooksAndExportFallback() {
  const root = "/Applications/Test.app/";
  const main = makeModule("Test", path.join(root, "Test"), 0, 0);
  const hooks = [];
  const { runtime } = loadAgent([main], {
    module: {
      getGlobalExportByName(name) {
        if (name === "dlopen") throw new Error("missing export");
        return null;
      },
    },
    attach: (address, callbacks) => hooks.push({ address, callbacks }),
  });
  runtime.rpc.exports.arm();
  assert.equal(hooks.length, 0);

  const fallback = loadAgent([main], {
    module: { findExportByName: (_module, name) => name },
    attach: (address, callbacks) => hooks.push({ address, callbacks }),
  });
  fallback.runtime.rpc.exports.arm();
  assert.deepEqual(hooks.map(({ address }) => address), ["dlopen", "dlopen_preflight"]);
  hooks[0].callbacks.onLeave();
}

function testInvalidHeadersAndMissingBundleRootsAreSkipped() {
  const root = "/Applications/Test.app/";
  const main = makeModule("Test", path.join(root, "Test"), 0, 0);
  const badMagic = makeModule("Bad", path.join(root, "Bad"), 4, 0, { magic: 0 });
  const noCommands = makeModule("NoCommands", path.join(root, "NoCommands"), 4, 0, { ncmds: 0 });
  const zeroCommand = makeModule("ZeroCommand", path.join(root, "ZeroCommand"), 4, 0, { cmdsize: 0 });
  const { runtime, messages } = loadAgent([main, badMagic, noCommands, zeroCommand]);
  runtime.rpc.exports.arm();
  assert.equal(messages.filter(({ payload }) => payload.event === "slice").length, 0);

  const noBundle = makeModule("Executable", "/usr/local/bin/executable", 4, 0);
  const fallback = loadAgent([noBundle], { mainModule: null });
  assert.equal(fallback.runtime.rpc.exports.arm(), null);
  assert.equal(fallback.messages.length, 0);
  assert.equal(loadAgent([], { mainModule: null }).runtime.rpc.exports.arm(), null);
}

function testHookCallbackContainsEnumerationFailure() {
  const root = "/Applications/Test.app/";
  const main = makeModule("Test", path.join(root, "Test"), 0, 0);
  const hooks = [];
  let enumerations = 0;
  const { runtime } = loadAgent([main], {
    enumerateModules: () => {
      enumerations += 1;
      if (enumerations > 1) throw new Error("enumeration failed");
      return [main];
    },
    module: { getGlobalExportByName: (name) => name },
    attach: (address, callbacks) => hooks.push({ address, callbacks }),
  });
  runtime.rpc.exports.arm();
  assert.equal(hooks.length, 2);
  assert.doesNotThrow(() => hooks[0].callbacks.onLeave());
}

testDecryptedDylibsAreDumped();
testArchitecturesBundleFallbackAndLargeRegions();
testSweepDeduplicatesAndSkipsBadModulesAndOutsideBundle();
testDlopenHooksAndExportFallback();
testInvalidHeadersAndMissingBundleRootsAreSkipped();
testHookCallbackContainsEnumerationFailure();
