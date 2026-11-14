"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const nullPointer = { isNull: () => true };

function entry(name, kind) {
  return {
    isNull: () => false,
    add: () => ({
      readUtf8String: () => name,
      readU16: () => name.length,
      readU8: () => kind,
    }),
  };
}

function loadPuller(ffi, files = {}) {
  const sourcePath = path.join(__dirname, "ipakeep_pull.js");
  const runtime = {
    NativeFunction: function (name) { return ffi[name]; },
    Module: { getGlobalExportByName: (name) => name },
    Memory: { allocUtf8String: (value) => value },
    File: class {
      static SEEK_END = -1;

      constructor(filePath) {
        this.bytes = files[filePath] ?? Buffer.alloc(0);
        this.offset = 0;
      }

      seek(offset, origin) {
        this.offset = origin === this.constructor.SEEK_END ? this.bytes.length + offset : offset;
      }

      tell() {
        return this.offset;
      }

      readBytes(length) {
        const result = this.bytes.subarray(this.offset, this.offset + length);
        this.offset += result.length;
        return result;
      }

      close() {}
    },
    rpc: { exports: {} },
  };
  vm.runInNewContext(fs.readFileSync(sourcePath, "utf8"), runtime, { filename: sourcePath });
  return runtime.rpc.exports;
}

function testDirectoryListingFiltersAndCloses() {
  const entries = [
    entry(".", 8),
    entry("..", 8),
    entry("folder", 4),
    entry("file", 8),
    entry("symlink", 10),
    nullPointer,
  ];
  let index = 0;
  let closed = 0;
  let openedPath;
  const api = loadPuller({
    opendir: (value) => {
      openedPath = value;
      return { isNull: () => false };
    },
    readdir: () => entries[index++],
    closedir: () => {
      closed += 1;
      return 0;
    },
  });
  assert.deepEqual(JSON.parse(JSON.stringify(api.listDirectory("/app"))), [
    { name: "folder", kind: "dir" },
    { name: "file", kind: "file" },
    { name: "symlink", kind: "other" },
  ]);
  assert.equal(openedPath, "/app");
  assert.equal(closed, 1);
}

function testDirectoryErrorsStillCloseAndReportOpenFailure() {
  let closed = 0;
  const failedRead = loadPuller({
    opendir: () => ({ isNull: () => false }),
    readdir: () => {
      throw new Error("read failed");
    },
    closedir: () => {
      closed += 1;
      return 0;
    },
  });
  assert.throws(() => failedRead.listDirectory("/broken"), /read failed/);
  assert.equal(closed, 1);

  const failedOpen = loadPuller({
    opendir: () => nullPointer,
    readdir: () => nullPointer,
    closedir: () => 0,
  });
  assert.throws(() => failedOpen.listDirectory("/missing"), /cannot open directory/);
}

function testFileSizeReadChunkAndCloseOnFailure() {
  const api = loadPuller({
    opendir: () => nullPointer,
    readdir: () => nullPointer,
    closedir: () => 0,
  }, { "/file": Buffer.from("abcdef") });
  assert.equal(api.fileSize("/file"), 6);
  assert.deepEqual([...api.readChunk("/file", 2, 3)], [...Buffer.from("cde")]);

  let closed = false;
  const runtime = {
    NativeFunction: function (name) {
      return ({
        opendir: () => nullPointer,
        readdir: () => nullPointer,
        closedir: () => 0,
      })[name];
    },
    Module: { getGlobalExportByName: (name) => name },
    Memory: { allocUtf8String: (value) => value },
    File: class {
      static SEEK_END = -1;
      seek() {}
      tell() {
        throw new Error("tell failed");
      }
      close() {
        closed = true;
      }
    },
    rpc: { exports: {} },
  };
  const sourcePath = path.join(__dirname, "ipakeep_pull.js");
  vm.runInNewContext(fs.readFileSync(sourcePath, "utf8"), runtime, { filename: sourcePath });
  assert.throws(() => runtime.rpc.exports.fileSize("/broken"), /tell failed/);
  assert.equal(closed, true);
}

testDirectoryListingFiltersAndCloses();
testDirectoryErrorsStillCloseAndReportOpenFailure();
testFileSizeReadChunkAndCloseOnFailure();
