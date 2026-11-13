"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

function writeU32(bytes, offset, value) {
  new DataView(bytes.buffer).setUint32(offset, value, true);
}

function makeModule(name, filePath, cryptsize, cryptid) {
  const bytes = new Uint8Array(512);
  for (const [offset, value] of [
    [0, 0xfeedfacf], [4, 0x0100000c], [8, 0], [16, 1],
    [32, 0x2c], [36, 24], [40, 128], [44, cryptsize], [48, cryptid],
  ]) writeU32(bytes, offset, value);
  bytes.fill(0x7f, 128, 128 + cryptsize);

  const pointer = (offset = 0) => ({
    add: (amount) => pointer(offset + amount),
    readU32: () => new DataView(bytes.buffer).getUint32(offset, true),
    readByteArray: (length) => bytes.slice(offset, offset + length).buffer,
  });
  return { name, path: filePath, base: pointer(), size: bytes.length };
}

function testDecryptedDylibsAreDumped() {
  const root = "/Applications/Test.app/";
  const main = makeModule("Test", path.join(root, "Test"), 0, 0);
  const dylib = makeModule("Framework", path.join(root, "Frameworks/Framework"), 32, 0);
  const modules = [main, dylib];
  const messages = [];
  const runtime = {
    Process: { mainModule: main, enumerateModules: () => modules },
    Module: { getGlobalExportByName: () => null },
    Interceptor: { attach: () => {} },
    rpc: { exports: {} },
    send: (payload, data) => messages.push({ payload, data }),
  };

  const source = fs.readFileSync(path.join(__dirname, "ipakeep_dump.js"), "utf8");
  vm.runInNewContext(source, runtime);
  runtime.rpc.exports.arm();

  const slice = messages.find(({ payload }) => payload.event === "slice");
  assert.equal(slice.payload.name, "Frameworks%2FFramework.arm64.bin");
  assert.equal(slice.payload.cryptsize, 32);
  assert.deepEqual([...new Uint8Array(slice.data)], Array(32).fill(0x7f));
}

testDecryptedDylibsAreDumped();
