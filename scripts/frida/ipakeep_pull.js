// Runs in Frida's system session (frida-server, unsandboxed) to read an
// installed app bundle exactly as it sits on disk: still FairPlay-encrypted,
// and therefore always the same build as the app that will be dumped.
const DT_DIR = 4;
const DT_REG = 8;

const opendir = new NativeFunction(Module.getGlobalExportByName('opendir'), 'pointer', ['pointer']);
const readdir = new NativeFunction(Module.getGlobalExportByName('readdir'), 'pointer', ['pointer']);
const closedir = new NativeFunction(Module.getGlobalExportByName('closedir'), 'int', ['pointer']);

// Darwin arm64 `struct dirent`: d_namlen @18 (u16), d_type @20 (u8), d_name @21.
function listDirectory(path) {
  const dir = opendir(Memory.allocUtf8String(path));
  if (dir.isNull()) {
    throw new Error('cannot open directory ' + path);
  }
  const entries = [];
  try {
    for (let entry = readdir(dir); !entry.isNull(); entry = readdir(dir)) {
      const name = entry.add(21).readUtf8String(entry.add(18).readU16());
      if (name === '.' || name === '..') {
        continue;
      }
      const type = entry.add(20).readU8();
      entries.push({ name, kind: type === DT_DIR ? 'dir' : type === DT_REG ? 'file' : 'other' });
    }
  } finally {
    closedir(dir);
  }
  return entries;
}

function fileSize(path) {
  const file = new File(path, 'rb');
  try {
    file.seek(0, File.SEEK_END);
    return file.tell();
  } finally {
    file.close();
  }
}

function readChunk(path, offset, length) {
  const file = new File(path, 'rb');
  try {
    file.seek(offset);
    return file.readBytes(length);
  } finally {
    file.close();
  }
}

rpc.exports = { listDirectory, fileSize, readChunk };
