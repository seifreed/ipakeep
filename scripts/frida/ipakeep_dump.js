'use strict';

// On-device FairPlay slice dumper for ipakeep.
//
// For every loaded Mach-O whose LC_ENCRYPTION_INFO(_64) has cryptid != 0, read
// the now-decrypted [cryptoff, cryptoff+cryptsize) region straight from memory
// and stream it back tagged with the exact filename `ipakeep decrypt inspect`
// prints (`<module-basename>.<arch>.bin`). `ipakeep decrypt patch --from <dir>`
// consumes those files. PAC (arm64e) signs code pointers, not data — raw
// Memory reads of the mapped region are unaffected.

const MH_MAGIC_64 = 0xfeedfacf;
const LC_ENCRYPTION_INFO = 0x21;
const LC_ENCRYPTION_INFO_64 = 0x2c;
const CPU_TYPE_ARM64 = 0x0100000c;
const CPU_TYPE_X86_64 = 0x01000007;
const CPU_SUBTYPE_ARM64E = 2;

function archLabel(cputype, cpusubtype) {
  const sub = cpusubtype & 0x00ffffff;
  if (cputype === CPU_TYPE_ARM64) return sub === CPU_SUBTYPE_ARM64E ? 'arm64e' : 'arm64';
  if (cputype === CPU_TYPE_X86_64) return 'x86_64';
  return 'cpu-' + cputype.toString(16);
}

function dumpModule(mod) {
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
        send({ event: 'slice', name: name, cryptoff: cryptoff, cryptsize: cryptsize }, data);
      }
      return;
    }
    cursor = cursor.add(cmdsize);
  }
}

rpc.exports = {
  dump: function () {
    const modules = Process.enumerateModules();
    let count = 0;
    for (const mod of modules) {
      try {
        dumpModule(mod);
        count++;
      } catch (e) {
        // Unreadable header / unmapped module — skip.
      }
    }
    send({ event: 'done', scanned: count });
  },
};
