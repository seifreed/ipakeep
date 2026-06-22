'use strict';

// On-device FairPlay slice dumper for ipakeep.
//
// For every loaded Mach-O *of the target app bundle* whose LC_ENCRYPTION_INFO(_64)
// has cryptid != 0, read the now-decrypted [cryptoff, cryptoff+cryptsize) region
// straight from memory and stream it back tagged with the exact filename
// `ipakeep decrypt inspect` prints (`<module-basename>.<arch>.bin`).
//
// Robustness vs the first version:
//   - Only the app bundle's own Mach-Os are dumped (not /usr/lib, /System, the
//     dyld shared cache), so output maps 1:1 to IPA entries.
//   - `arm()` installs a dlopen hook and does an initial sweep; frameworks loaded
//     lazily after launch are dumped as they map. `sweep()` is the final pass.
//   - Each module is sent at most once (dedup by name).
//
// PAC (arm64e) signs code pointers, not data — raw Memory reads of the mapped
// region are unaffected.

const MH_MAGIC_64 = 0xfeedfacf;
const LC_ENCRYPTION_INFO = 0x21;
const LC_ENCRYPTION_INFO_64 = 0x2c;
const CPU_TYPE_ARM64 = 0x0100000c;
const CPU_TYPE_X86_64 = 0x01000007;
const CPU_SUBTYPE_ARM64E = 2;

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

function dumpModule(mod) {
  if (sent.has(mod.name)) return;
  const base = mod.base;
  if (base.readU32() !== MH_MAGIC_64) return; // 64-bit Mach-O only
  const cputype = base.add(4).readU32();
  const cpusubtype = base.add(8).readU32();
  const ncmds = base.add(16).readU32();

  let cursor = base.add(32);
  for (let i = 0; i < ncmds; i++) {
    const cmd = cursor.readU32();
    const cmdsize = cursor.add(4).readU32();
    if (cmdsize === 0) break;
    if (cmd === LC_ENCRYPTION_INFO || cmd === LC_ENCRYPTION_INFO_64) {
      const cryptoff = cursor.add(8).readU32();
      const cryptsize = cursor.add(12).readU32();
      const cryptid = cursor.add(16).readU32();
      if (cryptid !== 0 && cryptsize > 0) {
        const name = mod.name + '.' + archLabel(cputype, cpusubtype) + '.bin';
        const data = base.add(cryptoff).readByteArray(cryptsize);
        sent.add(mod.name);
        send({ event: 'slice', name: name, cryptoff: cryptoff, cryptsize: cryptsize }, data);
      }
      return;
    }
    cursor = cursor.add(cmdsize);
  }
}

function sweep(root) {
  for (const mod of Process.enumerateModules()) {
    if (!inBundle(mod, root)) continue;
    try {
      dumpModule(mod);
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
