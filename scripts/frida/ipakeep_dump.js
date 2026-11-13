'use strict';

// On-device FairPlay slice dumper for ipakeep.
//
// For every loaded Mach-O *of the target app bundle* with an encrypted region,
// read the now-decrypted [cryptoff, cryptoff+cryptsize) region
// straight from memory and stream it back tagged with the exact filename
// `ipakeep decrypt inspect` prints: the module's path relative to the .app
// root with `%` and `/` escaped (`Frameworks%2FFoo.framework%2FFoo`), then
// `.<arch>.bin`.
//
// Each message is one file the bridge writes verbatim, so:
//   - regions over CHUNK_SIZE are sent as `<name>.part.<offset>` chunks that
//     `ipakeep decrypt patch` reassembles;
//   - the module's in-memory LC_UUID is sent as a `<name>.uuid` sidecar (hex
//     text) so the patcher can refuse a dump of a different build.
//
// Robustness vs the first version:
//   - Only the app bundle's own Mach-Os are dumped (not /usr/lib, /System, the
//     dyld shared cache), so output maps 1:1 to IPA entries.
//   - `arm()` installs a dlopen hook and does an initial sweep; frameworks loaded
//     lazily after launch are dumped as they map. `sweep()` is the final pass.
//   - Each module is sent at most once (dedup by full path).
//
// PAC (arm64e) signs code pointers, not data — raw Memory reads of the mapped
// region are unaffected.

const MH_MAGIC_64 = 0xfeedfacf;
const LC_UUID = 0x1b;
const LC_ENCRYPTION_INFO = 0x21;
const LC_ENCRYPTION_INFO_64 = 0x2c;
const CPU_TYPE_ARM64 = 0x0100000c;
const CPU_TYPE_X86_64 = 0x01000007;
const CPU_SUBTYPE_ARM64E = 2;
const CHUNK_SIZE = 16 * 1024 * 1024;

const sent = new Set();

function archLabel(cputype, cpusubtype) {
  const sub = cpusubtype & 0x00ffffff;
  if (cputype === CPU_TYPE_ARM64) return sub === CPU_SUBTYPE_ARM64E ? 'arm64e' : 'arm64';
  if (cputype === CPU_TYPE_X86_64) return 'x86_64';
  return 'cpu-' + cputype.toString(16);
}

// Root of the app bundle, e.g. "…/Bundle/Application/<uuid>/App.app/", derived
// from the main executable's path. Modules under it are the app's own code.
function bundleRoot() {
  const main = (typeof Process.mainModule !== 'undefined' && Process.mainModule)
    || Process.enumerateModules()[0];
  if (!main || !main.path) return null;
  const idx = main.path.indexOf('.app/');
  return idx >= 0 ? main.path.slice(0, idx + 5) : null;
}

function inBundle(mod, root) {
  return Boolean(root) && Boolean(mod.path) && mod.path.indexOf(root) === 0;
}

// Bundle-relative path escaped into one flat file name; must match
// `dump_filename` in src/infrastructure/decrypt/mod.rs.
function dumpName(mod, root, arch) {
  const relative = mod.path.slice(root.length);
  return relative.replace(/%/g, '%25').replace(/\//g, '%2F') + '.' + arch + '.bin';
}

function hexBytes(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += ('0' + bytes[i].toString(16)).slice(-2);
  return out.toUpperCase();
}

function asciiBuffer(text) {
  const bytes = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) bytes[i] = text.charCodeAt(i);
  return bytes.buffer;
}

// Walk the in-memory load commands for the encryption info and LC_UUID.
function readHeader(base) {
  const ncmds = base.add(16).readU32();
  const header = {
    cputype: base.add(4).readU32(),
    cpusubtype: base.add(8).readU32(),
    crypt: null,
    uuid: null,
  };
  let cursor = base.add(32);
  for (let i = 0; i < ncmds; i++) {
    const cmd = cursor.readU32();
    const cmdsize = cursor.add(4).readU32();
    if (cmdsize === 0) break;
    if (cmd === LC_ENCRYPTION_INFO || cmd === LC_ENCRYPTION_INFO_64) {
      header.crypt = { cryptoff: cursor.add(8).readU32(), cryptsize: cursor.add(12).readU32() };
    } else if (cmd === LC_UUID) {
      header.uuid = hexBytes(new Uint8Array(cursor.add(8).readByteArray(16)));
    }
    cursor = cursor.add(cmdsize);
  }
  return header;
}

function sendRegion(name, base, cryptoff, cryptsize) {
  if (cryptsize <= CHUNK_SIZE) {
    const data = base.add(cryptoff).readByteArray(cryptsize);
    send({ event: 'slice', name: name, cryptoff: cryptoff, cryptsize: cryptsize }, data);
    return;
  }
  for (let offset = 0; offset < cryptsize; offset += CHUNK_SIZE) {
    const length = Math.min(CHUNK_SIZE, cryptsize - offset);
    const data = base.add(cryptoff + offset).readByteArray(length);
    send(
      {
        event: 'slice',
        name: name + '.part.' + offset,
        cryptoff: cryptoff + offset,
        cryptsize: length,
        offset: offset,
        total: cryptsize,
      },
      data,
    );
  }
}

function dumpModule(mod, root) {
  if (sent.has(mod.path)) return;
  const base = mod.base;
  if (base.readU32() !== MH_MAGIC_64) return; // 64-bit Mach-O only
  const header = readHeader(base);
  // iOS clears cryptid in loaded dylibs after decrypting their pages.
  if (!header.crypt || header.crypt.cryptsize === 0) return;

  const name = dumpName(mod, root, archLabel(header.cputype, header.cpusubtype));
  sent.add(mod.path);
  if (header.uuid) {
    send(
      { event: 'slice', name: name + '.uuid', cryptoff: 0, cryptsize: header.uuid.length },
      asciiBuffer(header.uuid),
    );
  }
  sendRegion(name, base, header.crypt.cryptoff, header.crypt.cryptsize);
}

function sweep(root) {
  for (const mod of Process.enumerateModules()) {
    if (!inBundle(mod, root)) continue;
    try {
      dumpModule(mod, root);
    } catch (e) {
      // Unreadable header / unmapped module — skip.
    }
  }
}

function findExport(name) {
  if (typeof Module.getGlobalExportByName === 'function') {
    try {
      return Module.getGlobalExportByName(name);
    } catch (e) {
      return null;
    }
  }
  return Module.findExportByName(null, name);
}

rpc.exports = {
  // Install the dlopen hook (to catch lazily-loaded frameworks) and dump what is
  // already mapped. Returns the detected bundle root for diagnostics.
  arm: function () {
    const root = bundleRoot();
    for (const sym of ['dlopen', 'dlopen_preflight']) {
      const addr = findExport(sym);
      if (!addr) continue;
      Interceptor.attach(addr, {
        onLeave() {
          try {
            sweep(root);
          } catch (e) {}
        },
      });
    }
    sweep(root);
    return root;
  },
  // Final sweep after the app has settled; reports how many slices were sent.
  sweep: function () {
    sweep(bundleRoot());
    send({ event: 'done', dumped: sent.size });
  },
};
