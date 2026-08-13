// ============================================================================
// PS4 13.52 — Runtime Offset Scanner
// ============================================================================
// Coloque este script no console do navegador APÓS window.p estar ativo.
// Ele escaneia a memória em runtime para descobrir todos os offsets
// necessários para o 13.52.js (slopkit port).
//
// Uso: loadScript("runtime_scanner.js") ou colar no console.
// ============================================================================

const SCAN_START = 0x800000000;
const SCAN_END   = 0x900000000;
const STEP       = 0x4000;        // page size

// ─── Helpers ───────────────────────────────────────────────────────────────

function readString(addr, maxLen = 200) {
    let s = "";
    for (let i = 0; i < maxLen; i++) {
        let c = p.read1(addr + i);
        if (c === 0) break;
        s += String.fromCharCode(c);
    }
    return s;
}

function readU64(addr) {
    let v = p.read8(addr);
    return (BigInt(v.hi) << 32n) | BigInt(v.low >>> 0);
}

function u64ToInt64(big) {
    let low = Number(big & 0xFFFFFFFFn) >>> 0;
    let hi  = Number(big >> 32n) >>> 0;
    return new int64(low, hi);
}

function int64ToBig(v) {
    return (BigInt(v.hi) << 32n) | BigInt(v.low >>> 0);
}

function addrNum(addr) {
    if (typeof addr === "number") return addr;
    if (typeof addr === "bigint") return Number(addr);
    if (addr.low !== undefined && addr.hi !== undefined)
        return Number(int64ToBig(addr));
    return Number(addr);
}

function addrStr(addr) {
    let n = addrNum(addr);
    return "0x" + n.toString(16).padStart(16, "0");
}

// ─── 1. Encontrar bases ELF ────────────────────────────────────────────────

function findElfBases(start, end) {
    const bases = [];
    for (let addr = start; addr < end; addr += STEP) {
        try {
            let magic = p.read4(addr);
            if (magic === 0x464c457f) { // \x7fELF LE
                bases.push(addr);
            }
        } catch (e) {}
    }
    return bases;
}

// ─── 2. Identificar módulos ────────────────────────────────────────────────

function identifyModule(base) {
    // Ler strings nas primeiras 4MB
    const checkStrings = [
        { str: "libkernel_web", name: "libkernel" },
        { str: "libkernel",     name: "libkernel" },
        { str: "pthread_create",name: "libkernel" },
        { str: "sceKernelGetCurrentCpu", name: "libkernel" },
        { str: "libSceLibcInternal", name: "libc" },
        { str: "memset",        name: "libc" },
        { str: "malloc",        name: "libc" },
        { str: "libSceNKWebKit",name: "webkit" },
        { str: "WebKit",        name: "webkit" },
    ];

    for (let off = 0; off < 0x400000; off += 0x40) {
        try {
            let s = readString(base + off, 80);
            for (let check of checkStrings) {
                if (s.includes(check.str)) return check.name;
            }
        } catch (e) {}
    }
    return "unknown";
}

// ─── 3. Scan de imports no WebKit ──────────────────────────────────────────

function findImportsToModule(wkBase, libBase, libSize, scanSize) {
    const imports = [];
    for (let off = 0; off < scanSize; off += 8) {
        try {
            let ptr = readU64(wkBase + off);
            if (ptr >= BigInt(libBase) && ptr < BigInt(libBase + libSize)) {
                imports.push({ wkOffset: off, target: Number(ptr) });
            }
        } catch (e) {}
    }
    return imports;
}

// ─── 4. Identificar memset ─────────────────────────────────────────────────

function isMemset(addr) {
    try {
        // memset típico x86_64: mov rax, rdi  (48 89 F8)
        // ou: mov rdi, rdi / test rdx, rdx
        let b0 = p.read1(addr);
        let b1 = p.read1(addr + 1);
        let b2 = p.read1(addr + 2);
        // Padrões comuns de memset no PS4
        if (b0 === 0x48 && b1 === 0x89 && b2 === 0xF8) return true; // mov rax, rdi
        if (b0 === 0x48 && b1 === 0x85 && b2 === 0xD2) return true; // test rdx, rdx
        if (b0 === 0x48 && b1 === 0x89 && b2 === 0xF7) return true; // mov rdi, rsi
    } catch (e) {}
    return false;
}

// ─── 5. Identificar __stack_chk_guard ──────────────────────────────────────

function isStackChkGuard(addr) {
    try {
        let val = readU64(addr);
        // __stack_chk_guard é um canary. No PS4:
        // - Geralmente byte menos significativo = 0x00
        // - Não é ponteiro para código (não começa com 0x8... típico)
        // - É um valor "aleatório" mas pequeno (48 bits)
        let low = Number(val & 0xFFFFFFFFn);
        // Heurística: byte 0 == 0x00 e valor não é zero
        if ((low & 0xFF) === 0x00 && val !== 0n) {
            // Verificar se não aponta para código (não está na faixa 0x8xxxxxxxxx)
            let ptrVal = Number(val);
            if (ptrVal < 0x7000000000 || ptrVal > 0x9000000000) {
                return true;
            }
        }
    } catch (e) {}
    return false;
}

// ─── 6. Scan de gadgets ────────────────────────────────────────────────────

function findGadgets(base, size) {
    const gadgets = {};
    const patterns = {
        "ret":        { bytes: [0xC3], mask: [0xFF] },
        "pop rdi":    { bytes: [0x5F, 0xC3], mask: [0xFF, 0xFF] },
        "pop rsi":    { bytes: [0x5E, 0xC3], mask: [0xFF, 0xFF] },
        "pop rdx":    { bytes: [0x5A, 0xC3], mask: [0xFF, 0xFF] },
        "pop rcx":    { bytes: [0x59, 0xC3], mask: [0xFF, 0xFF] },
        "pop rax":    { bytes: [0x58, 0xC3], mask: [0xFF, 0xFF] },
        "pop rsp":    { bytes: [0x5C, 0xC3], mask: [0xFF, 0xFF] },
        "pop r8":     { bytes: [0x41, 0x58, 0xC3], mask: [0xFF, 0xFF, 0xFF] },
        "pop r9":     { bytes: [0x41, 0x59, 0xC3], mask: [0xFF, 0xFF, 0xFF] },
        "mov [rdi], rsi": { bytes: [0x48, 0x89, 0x37, 0xC3], mask: [0xFF, 0xFF, 0xFF, 0xFF] },
        "mov [rdi], rax": { bytes: [0x48, 0x89, 0x07, 0xC3], mask: [0xFF, 0xFF, 0xFF, 0xFF] },
        "mov [rdi], eax": { bytes: [0x89, 0x07, 0xC3], mask: [0xFF, 0xFF, 0xFF] },
        "mov rax, [rax]": { bytes: [0x48, 0x8B, 0x00, 0xC3], mask: [0xFF, 0xFF, 0xFF, 0xFF] },
        "add rax, rcx":   { bytes: [0x48, 0x01, 0xC8, 0xC3], mask: [0xFF, 0xFF, 0xFF, 0xFF] },
    };

    // Buffer para ler em chunks de 8 bytes (mais rápido)
    for (let off = 0; off < size; off += 8) {
        try {
            let qword = readU64(base + off);
            // Extrair 8 bytes do qword
            let bytes = [];
            let tmp = qword;
            for (let i = 0; i < 8; i++) {
                bytes.push(Number(tmp & 0xFFn));
                tmp >>= 8n;
            }

            for (let [name, pat] of Object.entries(patterns)) {
                if (gadgets[name]) continue;
                let patLen = pat.bytes.length;
                // Tentar alinhar o padrão nos 8 bytes lidos
                for (let start = 0; start <= 8 - patLen; start++) {
                    let match = true;
                    for (let i = 0; i < patLen; i++) {
                        if ((bytes[start + i] & pat.mask[i]) !== pat.bytes[i]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) {
                        gadgets[name] = off + start;
                        break;
                    }
                }
            }
        } catch (e) {}
    }
    return gadgets;
}

// ─── 7. Scan de syscalls ───────────────────────────────────────────────────

function findSyscalls(lkBase, size) {
    const syscalls = {};
    for (let off = 0; off < size; off += 1) {
        try {
            // Padrão: 48 C7 C0 XX XX XX XX 49 89 CA 0F 05 C3
            if (p.read1(lkBase + off)      === 0x48 &&
                p.read1(lkBase + off + 1)  === 0xC7 &&
                p.read1(lkBase + off + 2)  === 0xC0 &&
                p.read1(lkBase + off + 7)  === 0x49 &&
                p.read1(lkBase + off + 8)  === 0x89 &&
                p.read1(lkBase + off + 9)  === 0xCA &&
                p.read1(lkBase + off + 10) === 0x0F &&
                p.read1(lkBase + off + 11) === 0x05 &&
                p.read1(lkBase + off + 12) === 0xC3) {

                let num = p.read4(lkBase + off + 3);
                syscalls[num] = off;
            }
        } catch (e) {}
    }
    return syscalls;
}

// ─── 8. Achar _thread_list na libkernel ───────────────────────────────────

function findThreadList(lkBase, lkSize) {
    // _thread_list é um ponteiro global na libkernel.
    // Heurística: procurar na seção .data (após o código, ~0x50000+)
    // por um qword que aponta para uma estrutura pthread válida.
    // Uma pthread válida tem:
    //   +0x38 = next_thread (outro ponteiro ou 0)
    //   +0xA8 = stack_addr (ponteiro para stack, ~0x7fff...)
    //   +0xB0 = stack_size (0x80000 para worker)
    const dataStart = lkBase + 0x50000;
    const dataEnd   = lkBase + Math.min(lkSize, 0x300000);

    for (let off = dataStart; off < dataEnd; off += 8) {
        try {
            let threadPtr = readU64(off);
            if (threadPtr === 0n) continue;
            let tp = Number(threadPtr);
            if (tp < 0x100000000 || tp > 0xffffffffffff) continue;

            // Verificar stack_addr em +0xA8
            let stackAddr = readU64(tp + 0xA8);
            let stackSize = readU64(tp + 0xB0);

            // Stack addr deve ser um ponteiro válido (alta memória)
            let sa = Number(stackAddr);
            if (sa > 0x7000000000 && sa < 0x8000000000 &&
                stackSize === 0x80000n) {
                // Verificar next_thread em +0x38
                let next = readU64(tp + 0x38);
                let n = Number(next);
                if (n === 0 || (n > 0x100000000 && n < 0xffffffffffff)) {
                    return off - lkBase; // retorna offset relativo à base
                }
            }
        } catch (e) {}
    }
    return -1;
}

// ─── 9. Achar worker_wait_return na libkernel ──────────────────────────────

function findWorkerWaitReturn(lkBase, lkSize) {
    // worker_wait_return é o endereço de retorno do worker no idle loop.
    // No PS4, é geralmente uma função pequena na libkernel.
    // Heurística: procurar por um padrão de loop de espera.
    // Padrão típico (simplificado):
    //   mov rax, qword ptr [rdi+0x...]
    //   test rax, rax
    //   jz ...
    // Ou simplesmente procurar por "sceKernelUsleep" ou similar.
    //
    // Alternativa mais prática: o endereço costuma estar próximo de
    // pthread_exit e pthread_join. Vamos fazer um scan por funções
    // que contêm "scePthread" e têm um padrão de loop.
    //
    // Para simplificar, vamos procurar por um padrão de syscall sleep
    // ou um padrão de spinlock.
    for (let off = 0; off < lkSize; off += 1) {
        try {
            // Procurar por: 48 8B 47 38 (mov rax, [rdi+0x38]) seguido de test
            if (p.read1(lkBase + off)     === 0x48 &&
                p.read1(lkBase + off + 1) === 0x8B &&
                p.read1(lkBase + off + 2) === 0x47 &&
                p.read1(lkBase + off + 3) === 0x38) {
                // Verificar se há um test rax, rax ou similar nas próximas instruções
                let b4 = p.read1(lkBase + off + 4);
                let b5 = p.read1(lkBase + off + 5);
                if (b4 === 0x48 && b5 === 0x85) {
                    return off;
                }
            }
        } catch (e) {}
    }
    return -1;
}

// ─── MAIN ────────────────────────────────────────────────────────────────────

async function main() {
    console.log("=== PS4 13.52 Runtime Offset Scanner ===");
    console.log("WebKit base conhecida:", addrStr(window.wkBase || 0));

    // 1. Achar bases ELF
    console.log("\n[1/8] Scanning ELF headers...");
    const bases = findElfBases(SCAN_START, SCAN_END);
    console.log("Módulos encontrados:", bases.length);

    const moduleMap = {};
    for (const base of bases) {
        const name = identifyModule(base);
        if (name !== "unknown" && !moduleMap[name]) {
            moduleMap[name] = base;
            console.log(`  ${name}: ${addrStr(base)}`);
        }
    }

    if (!moduleMap.webkit && window.wkBase) {
        moduleMap.webkit = window.wkBase;
    }

    if (!moduleMap.webkit) {
        console.error("ERRO: WebKit base não encontrada! Defina window.wkBase antes.");
        return;
    }

    const wkBase = moduleMap.webkit;
    const lkBase = moduleMap.libkernel || 0;
    const lcBase = moduleMap.libc || 0;

    if (!lkBase || !lcBase) {
        console.error("ERRO: libkernel ou libc não encontrados!");
        return;
    }

    // 2. Achar imports
    console.log("\n[2/8] Scanning WebKit imports...");
    const libcImports = findImportsToModule(wkBase, lcBase, 0x400000, 0x4000000);
    const lkImports   = findImportsToModule(wkBase, lkBase, 0x400000, 0x4000000);
    console.log(`  Imports para libc: ${libcImports.length}`);
    console.log(`  Imports para libkernel: ${lkImports.length}`);

    // 3. Identificar memset
    console.log("\n[3/8] Identifying memset import...");
    let wk_memset_import = -1;
    let lc_memset = -1;
    for (const imp of libcImports) {
        if (isMemset(imp.target)) {
            wk_memset_import = imp.wkOffset;
            lc_memset = imp.target - lcBase;
            console.log(`  memset: wkOffset=0x${wk_memset_import.toString(16)}, lcOffset=0x${lc_memset.toString(16)}`);
            break;
        }
    }
    if (wk_memset_import === -1) {
        console.warn("  AVISO: memset não identificado!");
    }

    // 4. Identificar __stack_chk_guard
    console.log("\n[4/8] Identifying __stack_chk_guard import...");
    let wk_scg_import = -1;
    let lk_scg = -1;
    for (const imp of lkImports) {
        if (isStackChkGuard(imp.target)) {
            wk_scg_import = imp.wkOffset;
            lk_scg = imp.target - lkBase;
            console.log(`  __stack_chk_guard: wkOffset=0x${wk_scg_import.toString(16)}, lkOffset=0x${lk_scg.toString(16)}`);
            break;
        }
    }
    if (wk_scg_import === -1) {
        console.warn("  AVISO: __stack_chk_guard não identificado!");
    }

    // 5. Gadgets
    console.log("\n[5/8] Scanning WebKit gadgets...");
    const gadgets = findGadgets(wkBase, 0x2000000);
    for (let [name, off] of Object.entries(gadgets)) {
        console.log(`  ${name}: 0x${off.toString(16)}`);
    }

    // 6. Syscalls
    console.log("\n[6/8] Scanning libkernel syscalls...");
    const syscalls = findSyscalls(lkBase, 0x200000);
    let scCount = 0;
    for (let [num, off] of Object.entries(syscalls)) {
        scCount++;
    }
    console.log(`  Syscalls encontrados: ${scCount}`);
    // Printar alguns importantes
    const important = [0x14, 0x1, 0x3, 0x4, 0x5, 0x6, 0x7, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C];
    for (let num of important) {
        if (syscalls[num] !== undefined) {
            console.log(`  syscall 0x${num.toString(16)}: 0x${syscalls[num].toString(16)}`);
        }
    }

    // 7. _thread_list
    console.log("\n[7/8] Scanning _thread_list...");
    let threadListOff = findThreadList(lkBase, 0x400000);
    if (threadListOff !== -1) {
        console.log(`  _thread_list: 0x${threadListOff.toString(16)}`);
    } else {
        console.warn("  AVISO: _thread_list não encontrado!");
    }

    // 8. worker_wait_return
    console.log("\n[8/8] Scanning worker_wait_return...");
    let workerWaitOff = findWorkerWaitReturn(lkBase, 0x200000);
    if (workerWaitOff !== -1) {
        console.log(`  worker_wait_return: 0x${workerWaitOff.toString(16)}`);
    } else {
        console.warn("  AVISO: worker_wait_return não encontrado!");
    }

    // ─── Gerar output no formato 13.52.js ──────────────────────────────────
    console.log("\n" + "=".repeat(70));
    console.log("// === OUTPUT PARA 13.52.js ===");
    console.log("=".repeat(70));

    let out = [];
    out.push(`// PS4 13.52 — Offsets descobertos em runtime`);
    out.push(`// WebKit Base: ${addrStr(wkBase)}`);
    out.push(`// Libkernel Base: ${addrStr(lkBase)}`);
    out.push(`// Libc Base: ${addrStr(lcBase)}`);
    out.push(``);
    out.push(`const OFFSET_wk_host_constructor_candidates = [`);
    out.push(`  0x${(window.__ps5NativeCtor - wkBase).toString(16)} // __ps5NativeCtor - wkBase`);
    out.push(`];`);
    out.push(``);
    out.push(`const OFFSET_wk_vtable_first_element = 0x0; // não usado no 9.00+`);
    if (wk_memset_import !== -1) {
        out.push(`const OFFSET_wk_memset_import = 0x${wk_memset_import.toString(16)};`);
    } else {
        out.push(`const OFFSET_wk_memset_import = 0x0; // PREENCHER MANUALMENTE`);
    }
    if (wk_scg_import !== -1) {
        out.push(`const OFFSET_wk___stack_chk_guard_import = 0x${wk_scg_import.toString(16)};`);
    } else {
        out.push(`const OFFSET_wk___stack_chk_guard_import = 0x0; // PREENCHER MANUALMENTE`);
    }
    out.push(``);
    if (lc_memset !== -1) {
        out.push(`const OFFSET_lc_memset = 0x${lc_memset.toString(16)};`);
    } else {
        out.push(`const OFFSET_lc_memset = 0x0; // PREENCHER MANUALMENTE`);
    }
    out.push(`const OFFSET_lc_malloc = 0x0; // TODO`);
    out.push(`const OFFSET_lc_free = 0x0; // TODO`);
    out.push(`const OFFSET_lc_memcpy = 0x0; // TODO`);
    out.push(`const OFFSET_lc_setjmp = 0x0; // TODO`);
    out.push(`const OFFSET_lc_longjmp = 0x0; // TODO`);
    out.push(``);
    if (lk_scg !== -1) {
        out.push(`const OFFSET_lk___stack_chk_guard = 0x${lk_scg.toString(16)};`);
    } else {
        out.push(`const OFFSET_lk___stack_chk_guard = 0x0; // PREENCHER MANUALMENTE`);
    }
    out.push(`const OFFSET_lk_pthread_create_name_np = 0x0; // TODO`);
    out.push(`const OFFSET_lk_pthread_join = 0x0; // TODO`);
    out.push(`const OFFSET_lk_pthread_exit = 0x0; // TODO`);
    out.push(`const OFFSET_lk_scePthreadCreate = 0x0; // TODO`);
    out.push(`const OFFSET_lk_scePthreadJoin = 0x0; // TODO`);
    out.push(`const OFFSET_lk_scePthreadAttrInit = 0x0; // TODO`);
    out.push(`const OFFSET_lk_scePthreadAttrSetstacksize = 0x0; // TODO`);
    out.push(`const OFFSET_lk_scePthreadAttrSetdetachstate = 0x0; // TODO`);
    out.push(`const OFFSET_lk_scePthreadAttrDestroy = 0x0; // TODO`);
    out.push(`const OFFSET_lk_sceKernelSendNotificationRequest = 0x0; // TODO`);
    out.push(`const OFFSET_lk_getpid = 0x0; // TODO`);
    if (threadListOff !== -1) {
        out.push(`const OFFSET_lk__thread_list = 0x${threadListOff.toString(16)};`);
    } else {
        out.push(`const OFFSET_lk__thread_list = 0x0; // PREENCHER MANUALMENTE`);
    }
    if (workerWaitOff !== -1) {
        out.push(`const OFFSET_lk_worker_wait_return = 0x${workerWaitOff.toString(16)};`);
    } else {
        out.push(`const OFFSET_lk_worker_wait_return = 0x0; // PREENCHER MANUALMENTE`);
    }
    out.push(`const OFFSET_lk_sleep = 0x0; // TODO`);
    out.push(`const OFFSET_lk_sceKernelGetCurrentCpu = 0x0; // TODO`);
    out.push(``);
    out.push(`let wk_gadgetmap = {`);
    for (let [name, off] of Object.entries(gadgets)) {
        out.push(`  "${name}": 0x${off.toString(16)},`);
    }
    out.push(`};`);
    out.push(``);
    out.push(`let syscall_map = {`);
    // Ordenar syscalls
    let scKeys = Object.keys(syscalls).map(Number).sort((a,b)=>a-b);
    for (let num of scKeys) {
        out.push(`  0x${num.toString(16).padStart(3,"0")}: 0x${syscalls[num].toString(16)},`);
    }
    out.push(`};`);

    let finalOutput = out.join("\n");
    console.log(finalOutput);

    // Tentar salvar em window.scannerOutput para fácil cópia
    window.scannerOutput = finalOutput;
    console.log("\n[OK] Output salvo em window.scannerOutput");
}

// Executar
main().catch(e => console.error("Scanner falhou:", e));
