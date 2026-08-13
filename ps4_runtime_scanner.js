// ============================================================================
// PS4 13.52 — Runtime Offset Scanner (Blindado contra Crash)
// ============================================================================

const SCAN_START = 0x800000000;
const SCAN_END   = 0x820000000; // Reduzido para o range seguro do Userland do WebKit/Módulos
const STEP       = 0x4000;      // 16KB (page size)

function readString(addr, maxLen = 100) {
    let s = "";
    try {
        for (let i = 0; i < maxLen; i++) {
            let c = p.read1(addr + i);
            if (c === 0) break;
            s += String.fromCharCode(c);
        }
    } catch (e) {}
    return s;
}

function readU64(addr) {
    try {
        let v = p.read8(addr);
        return (BigInt(v.hi) << 32n) | BigInt(v.low >>> 0);
    } catch (e) {
        return 0n;
    }
}

function addrStr(addr) {
    let n = Number(addr);
    return "0x" + n.toString(16).padStart(16, "0");
}

async function runSafeScanner() {
    console.log("=== PS4 13.52 Runtime Scanner Seguro Iniciado ===");
    if (typeof window.log === "function") {
        window.log("[*] Scanner seguro iniciado em background...", 1);
    }

    const wkBase = window.wkBase || 0;
    console.log("WebKit Base informada:", addrStr(wkBase));

    if (!wkBase) {
        console.error("ERRO: wkBase não definida!");
        if (typeof window.log === "function") window.log("[-] Erro: WebKit Base não encontrada para o scanner.", 4);
        return;
    }

    // Validação segura dos headers ELF sem crashar
    console.log("[*] Buscando assinaturas de módulos carregados...");
    const bases = [];
    
    // Varredura segura em saltos de página ao redor da base conhecida do WebKit
    const searchStart = wkBase - 0x2000000; // 32MB antes
    const searchEnd   = wkBase + 0x4000000; // 64MB depois

    for (let addr = searchStart; addr < searchEnd; addr += STEP) {
        try {
            let magic = p.read4(addr);
            if (magic === 0x464c457f) { // Assinatura ELF (\x7fELF)
                bases.push(addr);
            }
        } catch (e) {
            // Ignora silenciosamente páginas protegidas ou não mapeadas
        }
    }

    console.log(`[+] Total de cabeçalhos ELF encontrados de forma segura: ${bases.length}`);
    if (typeof window.log === "function") {
        window.log(`[+] Módulos ELF detectados na RAM: ${bases.length}`, 5);
    }

    let lkBase = 0;
    let lcBase = 0;

    for (const base of bases) {
        let modName = "desconhecido";
        try {
            // Checa as primeiras páginas do ELF em busca do nome do módulo
            for (let off = 0; off < 0x10000; off += 0x100) {
                let s = readString(base + off, 60);
                if (s.includes("libkernel")) { modName = "libkernel"; lkBase = base; break; }
                if (s.includes("LibcInternal") || s.includes("libc")) { modName = "libc"; lcBase = base; break; }
                if (s.includes("WebKit")) { modName = "webkit"; break; }
            }
        } catch(e) {}
        console.log(`  -> Módulo ${modName} em: ${addrStr(base)}`);
        if (typeof window.log === "function") {
            window.log(`  [MOD] ${modName}: ${addrStr(base)}`, 1);
        }
    }

    console.log("=== Scanner Seguro Finalizado com Sucesso ===");
    if (typeof window.log === "function") {
        window.log("[+] Runtime scanner finalizado sem crashes!", 5);
    }
}

// Executa de forma assíncrona para não travar a UI
setTimeout(runSafeScanner, 500);
