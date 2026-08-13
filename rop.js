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

// ============================================================
// NOTIFICAÇÃO NATIVA PS4 13.52
// ============================================================

const NOTIFY_OFFSET = 0x19320;  // CONFIRMADO no libkernel 13.52 retail

/**
 * Envia uma notificação nativa do sistema PS4 via sceKernelSendNotificationRequest
 * @param {object} chain - instância de worker_rop (this.chain do main.js)
 * @param {object} p - primitiva R/W (this.p do main.js)
 * @param {string} text - mensagem a exibir (max ~1023 chars)
 * @param {string} iconName - nome do ícone (default: "icon_system")
 */
export async function sendNotification(chain, p, text, iconName = "icon_system") {
    if (!globalThis.p) throw new Error("window.p not installed");
    if (!lkBase) throw new Error("libkernelBase not resolved");

    // Endereço da função sceKernelSendNotificationRequest no libkernel
    const notifyFunc = lkBase.add32(NOTIFY_OFFSET);

    // Aloca buffer de 0xC30 (3120) bytes = sizeof(SceNotificationRequest)
    const bufSize = 0xC30;
    const buf = p.malloc(bufSize, 1);  // type=1 = Uint8Array

    // Zera o buffer inteiro
    for (let i = 0; i < bufSize; i++) {
        p.write1(buf.add32(i), 0);
    }

    // --- Preenche a estrutura SceNotificationRequest (packed) ---

    // type = 0 (Message) @ 0x00
    p.write4(buf.add32(0x00), 0);

    // reqId = 0 @ 0x04
    p.write4(buf.add32(0x04), 0);

    // priority = 0 @ 0x08
    p.write4(buf.add32(0x08), 0);

    // msgId = 0 @ 0x0C
    p.write4(buf.add32(0x0C), 0);

    // targetId = -1 @ 0x10
    p.write4(buf.add32(0x10), 0xFFFFFFFF);

    // userId = 0 @ 0x14
    p.write4(buf.add32(0x14), 0);

    // deviceId = 0 @ 0x18
    p.write4(buf.add32(0x18), 0);

    // addressingUserId = 0 @ 0x1C
    p.write4(buf.add32(0x1C), 0);

    // appId = 0 @ 0x20
    p.write4(buf.add32(0x20), 0);

    // errorNumber = 0 @ 0x24
    p.write4(buf.add32(0x24), 0);

    // attribute = 0 @ 0x28
    p.write4(buf.add32(0x28), 0);

    // hasIcon = 1 @ 0x2C
    p.write1(buf.add32(0x2C), 1);

    // message @ 0x2D (1024 bytes)
    const msgBytes = new TextEncoder().encode(text);
    for (let i = 0; i < msgBytes.length && i < 1023; i++) {
        p.write1(buf.add32(0x2D + i), msgBytes[i]);
    }
    // null terminator já está por causa do zero-fill

    // iconUri @ 0x42D (2048 bytes)
    const iconUri = "cxml://psnotification/tex_" + iconName;
    const iconBytes = new TextEncoder().encode(iconUri);
    for (let i = 0; i < iconBytes.length && i < 2047; i++) {
        p.write1(buf.add32(0x42D + i), iconBytes[i]);
    }

    console.log("[notify] Buffer preparado em: 0x" + buf.toString());
    console.log("[notify] sceKernelSendNotificationRequest @ 0x" + notifyFunc.toString());

    // --- Chama via ROP: sceKernelSendNotificationRequest(0, buf, 0xC30, 0) ---
    // Argumentos SysV x86_64: RDI, RSI, RDX, RCX, R8, R9
    // rdi = 0 (api = ToastPopup)
    // rsi = buf (ponteiro para SceNotificationRequest)
    // rdx = 0xC30 (size)
    // rcx = 0 (blocking = false)

    const result = await chain.call(notifyFunc, 0, buf, 0xC30, 0);

    console.log("[notify] Resultado: 0x" + result.toString());
    return result;
}
