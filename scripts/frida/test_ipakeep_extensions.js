"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function loadAgent(extensionExists) {
  const calls = [];
  const nullPointer = { isNull: () => true };
  const messageSend = (_target, selector, ...args) => {
    calls.push(selector.name);
    if (selector.name === "stringWithUTF8String:") return { value: args[0] };
    if (selector.name === "extensionWithIdentifier:error:") {
      return extensionExists ? { isNull: () => false } : nullPointer;
    }
    if (selector.name === "array") return { isNull: () => false };
    if (selector.name === "beginExtensionRequestWithInputItems:completion:") {
      args[1].callback();
      return nullPointer;
    }
    throw new Error("unexpected Objective-C selector " + selector.name);
  };
  const runtime = {
    NativeFunction: function (address) {
      const name = address.name;
      if (name === "objc_getClass") return (value) => ({ kind: "class", name: value });
      if (name === "sel_registerName") return (value) => ({ kind: "selector", name: value });
      if (name === "objc_msgSend") return messageSend;
      throw new Error("unexpected native function " + name);
    },
    NativeCallback: function (callback) { return callback; },
    Module: { getGlobalExportByName: (name) => ({ name }) },
    Memory: {
      allocUtf8String: (value) => value,
      alloc(size) {
        const memory = { size, callback: null, isNull: () => false };
        memory.add = (offset) => ({
          offset,
          writeU64() {},
          writeU32() {},
          writePointer(value) {
            if (size === 32 && offset === 16) memory.callback = value;
          },
        });
        memory.writeU64 = () => {};
        memory.writeU32 = () => {};
        memory.writePointer = () => {};
        return memory;
      },
    },
    Process: { pointerSize: 8 },
    ptr: () => nullPointer,
    rpc: { exports: {} },
  };
  const sourcePath = path.join(__dirname, "ipakeep_extensions.js");
  vm.runInNewContext(fs.readFileSync(sourcePath, "utf8"), runtime, { filename: sourcePath });
  return { launch: runtime.rpc.exports.launch, calls };
}

function testMissingExtensionReturnsFalse() {
  const agent = loadAgent(false);
  assert.equal(agent.launch("com.example.widget"), false);
  assert.deepEqual(agent.calls, ["stringWithUTF8String:", "extensionWithIdentifier:error:"]);
}

function testExtensionRequestRunsCompletionAndReturnsTrue() {
  const agent = loadAgent(true);
  assert.equal(agent.launch("com.example.widget"), true);
  assert.deepEqual(agent.calls, [
    "stringWithUTF8String:",
    "extensionWithIdentifier:error:",
    "array",
    "beginExtensionRequestWithInputItems:completion:",
  ]);
}

testMissingExtensionReturnsFalse();
testExtensionRequestRunsCompletionAndReturnsTrue();
