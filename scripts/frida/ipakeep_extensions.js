// Loaded into the running host app: asks iOS to start app extensions through
// NSExtension, the way the system would, so event-driven extensions
// (notification services, widgets) get a process the dumper can attach to.
// Frida 17 no longer bundles the ObjC bridge, so the runtime is called directly.
const fn = (name, ret, args) => new NativeFunction(Module.getGlobalExportByName(name), ret, args);
const objcGetClass = fn('objc_getClass', 'pointer', ['pointer']);
const selRegisterName = fn('sel_registerName', 'pointer', ['pointer']);
const objcMsgSend = Module.getGlobalExportByName('objc_msgSend');
const send0 = new NativeFunction(objcMsgSend, 'pointer', ['pointer', 'pointer']);
const send1 = new NativeFunction(objcMsgSend, 'pointer', ['pointer', 'pointer', 'pointer']);
const send2 = new NativeFunction(objcMsgSend, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);

const BLOCK_IS_GLOBAL = 1 << 28;
const retained = [];

const cls = (name) => objcGetClass(Memory.allocUtf8String(name));
const sel = (name) => selRegisterName(Memory.allocUtf8String(name));
const nsString = (value) => send1(cls('NSString'), sel('stringWithUTF8String:'), Memory.allocUtf8String(value));

function globalBlock(callback) {
  const invoke = new NativeCallback(callback, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);
  const descriptor = Memory.alloc(16);
  descriptor.writeU64(0);
  descriptor.add(8).writeU64(32);
  const block = Memory.alloc(32);
  block.writePointer(Module.getGlobalExportByName('_NSConcreteGlobalBlock'));
  block.add(8).writeU32(BLOCK_IS_GLOBAL);
  block.add(12).writeU32(0);
  block.add(16).writePointer(invoke);
  block.add(24).writePointer(descriptor);
  retained.push(invoke, descriptor, block);
  return block;
}

function launch(identifier) {
  const error = Memory.alloc(Process.pointerSize);
  error.writePointer(ptr(0));
  const extension = send2(cls('NSExtension'), sel('extensionWithIdentifier:error:'), nsString(identifier), error);
  if (extension.isNull()) {
    return false;
  }
  retained.push(extension);
  const items = send0(cls('NSArray'), sel('array'));
  send2(extension, sel('beginExtensionRequestWithInputItems:completion:'), items, globalBlock(() => {}));
  return true;
}

rpc.exports = { launch };
