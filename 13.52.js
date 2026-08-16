
// ============================================================
// PS4 FW 13.52 — Offsets para slopkit method
// Gerado por análise estática de:
//   libSceNKWebKit_sprx.decrypted   (70 MB)
//   libkernel_web_sprx.decrypted    (448 KB)
//   libSceLibcInternal_sprx.decrypted (1,5 MB)
//
// Convenção: file_offset = rva + 0x4000
//
// Confirmado via duas runs com ASLR diferente:
//   __ps5NativeCtor=0x8036F9E20 → base=0x800000000
//   __ps5NativeCtor=0x81CBF9E20 → base=0x819500000
// Offset fixo do host-constructor: 0x36F9E20 (~55.5 MB)
//
// Legenda de confiança:
//   [✓] Confirmado: NID localizado na symtab + disasm verificado
//   [~] Razoável:  padrão de código / NID cruzado com WebKit PLT
//   [?] Incerto:   candidato plausível, sem confirmação total
//   [!] Não encontrado: não exportado ou requer análise mais profunda
// ============================================================

// ── host-constructor candidates ──────────────────────────────
// webkitBase = nativeCtorAddr - hc
const OFFSET_wk_host_constructor_candidates = [
    0x36F9E20   // [✓] offset confirmado do __ps5NativeCtor
];

// ── libSceNKWebKit ───────────────────────────────────────────

// [✓] NID -x5vK4NNNYM (WKDownloadGetTypeID) — export da WebKit
//     file_offset = 0xC87A20 + 0x4000 = 0xC8BA20
const OFFSET_wk_vtable_first_element = 0x00C87A20;

// [~] NID j4ViWNHEgww — memset: alinha ptr (and al,0xf0) + fill SIMD
//     WebKit GOT slot para memset de libSceLibcInternal
//     file_offset = 0x03CB8C80 + 0x4000 = 0x03CBCC80  (seção de dados)
const OFFSET_wk_memset_import = 0x03CB8C80;

// [✓] NID zr094EQ39Ww — __stack_chk_guard (primeira ocorrência no GOT RELA)
//     Identificado pela frequência máxima de referência (>200× no GOT de WebKit)
//     file_offset = 0x03C2B648 + 0x4000 = 0x03C2F648
const OFFSET_wk___stack_chk_guard_import = 0x03C2B648;

// ── libSceLibcInternal ───────────────────────────────────────

// [~] NID j4ViWNHEgww  file_offset=0x2B580
//     prologue: mov rax,rdi | and al,0xf0 | vmovd xmm0,esi | vpshufb (broadcast byte)
//     seguido de vmovdqu stores  → padrão de memset SIMD
const OFFSET_lc_memset = 0x00027580;

// [✓] NID Q3VBxCXhUHs  file_offset=0x2AAD0
//     prologue: mov rax,rdi | add rax,rdx (dst+len) → overlap check SIMD
//     seguido de vmovdqu [rdi],xmm0 copy  → memcpy/memmove confirmado
const OFFSET_lc_memcpy = 0x00026AD0;

// [~] NID DYivN1nO-JQ  file_offset=0x8BB30
//     saves r15,r14,r13,r12,rbp — função mais complexa na região 0x087xxx
//     padrão consistente com alocador jemalloc (tamanho de bloco + classe)
const OFFSET_lc_malloc = 0x00087B30;

// [~] NID ayTeobcoGj8  file_offset=0x89670
//     saves r15,r14 — segunda função grande na região 0x089xxx (logo após malloc)
//     posição de ficheiro típica de free() depois de malloc()
const OFFSET_lc_free = 0x00089270;

// [?] NID 2w+4Mo2DPro  file_offset=0x48DA0
//     carrega de [rdi] e [rsi] com movzx + compare byte a byte
//     NOTA: padrão atípico (cmp rsi,rdx no prólogo) — pode ser strcmp ou bcmp
const OFFSET_lc_strcmp = 0x00044DA0;

// [?] NID 7glioH0t9HM  file_offset=0x48DE0
//     padrão idêntico a 2w+4Mo2DPro mas endereço consecutivo
//     possível variante memcmp (3 argumentos: rdi,rsi,rdx)
const OFFSET_lc_memcmp = 0x00044DE0;

// [~] NID eLdDw6l0-bU  file_offset=0x14C50
//     sub rsp,0xe8  (232 bytes de frame) → parser de format string
//     frame muito grande sugere vsnprintf com buffers locais
const OFFSET_lc_vsnprintf = 0x00010850;

// [~] NID sETNbyWsEHs  file_offset=0xD24F0
//     salva estado de sinal + registradores callee-saved em [rdi+N]
//     padrão sigsetjmp / setjmp com suporte a signal mask
const OFFSET_lc_setjmp = 0x000CE4F0;

// [~] NID SHlt7EhOtqA  file_offset=0xE5B0
//     mov r14,rsi | mov rbx,rdi → preserva (jmp_buf, val)
//     depois chama implementação interna do longjmp
const OFFSET_lc_longjmp = 0x0000A1B0;

// ── libkernel_web ─────────────────────────────────────────────

// [✓] NID f7uOxY9mM1U — data symbol (STT_OBJECT), RVA=0x61410
//     Referenciado por 666 funções via [rip+offset] → mais referenciado
//     __stack_chk_guard é o símbolo de dados mais ubíquo em código protegido
//     file_offset = 0x61410 + 0x4000 = 0x65410
const OFFSET_lk___stack_chk_guard = 0x00061410;

// [~] NID a2P9wYGeZvc  file_offset=0x1F9B0
//     saves r15,r14,r13,r12,rbp (5 registradores!) — implementação completa
//     chama _umtx_op; assinatura de 5 args (thread,attr,fn,arg,name)
//     → pthread_create_name_np  (versão BSD com nome de thread)
const OFFSET_lk_pthread_create_name_np = 0x0001B9B0;

// [~] NID JNkVVsVDmOk  file_offset=0x1F590
//     mov eax,0x16 | test rdi,rdi | je ret | test rsi,rsi | je ret
//     | mov rcx,[rdi] | cmp dword[rcx+4],expected_state
//     chama _umtx_op para esperar; 2 args (thread_t*, void**) → pthread_join
const OFFSET_lk_pthread_join = 0x0001B590;

// [✓] NID FJrT5LuUBAU  file_offset=0x27BC0
//     xor esi,esi | call 0xe070 | ud2
//     'ud2' após call confirma: função que nunca retorna → pthread_exit
const OFFSET_lk_pthread_exit = 0x000235C0;

// [~] NID W0Hpm2X0uPE  file_offset=0x17530
//     exportado nos namespaces libkernel E libScePosix
//     call 0x1b9b0 (pthread_create_name_np) + conversão de erro SCE
//     → scePthreadCreate (libkernel) / pthread_create (libScePosix)
const OFFSET_lk_scePthreadCreate = 0x00013530;

// [~] NID JNkVVsVDmOk  mesmo RVA que pthread_join acima
//     exportado também no namespace libkernel → scePthreadJoin
const OFFSET_lk_scePthreadJoin = 0x0001B590;

// [✓] NID nu4a0-arQis  file_offset=0x2A010
//     vmovups ymm0,[rip+0x11408] | vmovups [rdi],ymm0  (32 bytes defaults)
//     vmovups xmm1,[rip+0x113e0] | vmovups [rdi+0x20],xmm1 (16 bytes)
//     mov qword[rdi+0x30],0 | mov dword[rdi+0x38],0
//     inicializa struct ScePthreadAttr com valores default → scePthreadAttrInit
const OFFSET_lk_scePthreadAttrInit = 0x00026010;

// [!] Não identificado com confiança suficiente
//     NOTA: tG+805b1Njk@0x16260 (cmp rdi,0x4000; store [global+0x20])
//     parece sceKernelSetProcessStackSize, NÃO scePthreadAttrSetstacksize
//     TODO: buscar função 2-arg que valida rsi≥min e armazena em [rdi+offset]
const OFFSET_lk_scePthreadAttrSetstacksize = 0x0;

// [~] NID xesmlSI-KCI  file_offset=0x233F0
//     mov eax,0x16 | test rdi,rdi (NULL check attr) | je ret
//     test esi,0xfffffffd | jne ret  ← aceita apenas 0 ou 2 (JOINABLE/DETACHED)
//     mov rcx,[rdi] → acessa attr interno
//     → scePthreadAttrSetdetachstate (valida estado de detach)
const OFFSET_lk_scePthreadAttrSetdetachstate = 0x0001F3F0;

// [?] NID o7O4z3jwKzo  file_offset=0x1CE80
//     push rbp | call 0x2d740 | test eax,eax | js error | pop rbp | ret
//     wrapper mínimo em torno de syscall de limpeza → candidato a AttrDestroy
const OFFSET_lk_scePthreadAttrDestroy = 0x00018E80;

// [!] Syscall PS4-específico (>500), não identificado sem banco de dados de NIDs
//     Candidatos PS4 neste binário: NIDs zdaF5N-Xe2M(560),
//     nZHk+lpqwVQ(594), GQli4UAXTfQ(595), O-hEvSnv2o4(606)
//     TODO: cruzar com NID database da comunidade homebrew PS4
const OFFSET_lk_sceKernelSendNotificationRequest = 0x0;

// [~] NID XVL8So3QJUk  file_offset=0x2CA40
//     saves r15,r14,r13,r12 (função de 5 args)
//     chama __sysctl @ 0x2D5A0 (syscall #202) internamente
//     exportado como libScePosix e libkernel → sysctlbyname
const OFFSET_lk_sysctlbyname = 0x00028A40;

// [~] NID W0Hpm2X0uPE  mesmo RVA que scePthreadCreate acima
//     exportado no namespace libScePosix → pthread_create (POSIX)
const OFFSET_lk_pthread_create = 0x00013530;

// [✓] NID HoLVWNanBBc  file_offset=0x30B70
//     syscall wrapper com mov eax,0x14 (syscall #20 FreeBSD = getpid)
//     confirmado por análise de 1660 símbolos de libkernel_web
const OFFSET_lk_getpid = 0x0002CB70;

// [!] Símbolo interno (_thread_list), não está na tabela de exportação
//     Em libpthread FreeBSD é uma variável global de lista encadeada de threads
//     Requer análise mais profunda dos internos do pthread
const OFFSET_lk__thread_list = 0x0;

// [✓] Instrução pós-syscall dentro de _umtx_op @ RVA 0x2BAC0
//     _umtx_op (syscall #454) → instrução APÓS 'syscall' = endereço de retorno
//     worker threads bloqueadas em _umtx_op têm este endereço no topo do stack
//     file_offset = 0x2BACC + 0x4000 = 0x2FACC
const OFFSET_lk_worker_wait_return = 0x0002BACC;

// [✓] NID 3e+4Iv7IJ8U  file_offset=0x21870
//     exportado de libScePosix; primeiros 60 bytes chamam nanosleep @ 0x2D4C0
//     nanosleep é syscall #240 confirmado → sleep(seconds) chama nanosleep
const OFFSET_lk_sleep = 0x0001D870;

// [✓] NID g0VTBxfJyu0  file_offset=0x180C0
//     cpuid (leaf 1) → extrai APIC ID de EBX[31:24]
//     calcula 7 - (ebx>>24) → CPU ID lógico (0-7 para PS4 8-core)
//     único símbolo de libkernel com instrução 'cpuid'
const OFFSET_lk_sceKernelGetCurrentCpu = 0x000140C0;

// [!] Syscall PS4-específico, não identificado
//     sceKernelDlsym provavelmente usa syscall na faixa 540-600
//     TODO: cruzar NIDs dos syscalls PS4 com NID database
const OFFSET_lk_sceKernelDlsym = 0x0;

// ── libSceLibcInternal (extras não na lista WebKit PLT principal) ──

// [~] NID Q3VBxCXhUHs — já listado como lc_memcpy
//     (mesmo NID importado por WebKit GOT=0x03CB8C38)
const OFFSET_lc_memcpy_wk_import = 0x03CB8C38; // GOT slot no WebKit

// ── Gadgets e Syscalls ────────────────────────────────────────

// Mapa de gadgets ROP do WebKit (a preencher conforme análise ROP)
let wk_gadgetmap = {};

// Mapa de syscalls — NIDs PS4-específicos identificados (>500)
// syscall#  NID em libkernel_web
let syscall_map = {
    535: 'XujojypwYYc',   // PS4-específico
    536: 'YbAunrti+54',   // PS4-específico
    560: 'zdaF5N-Xe2M',   // PS4-específico
    594: 'nZHk+lpqwVQ',   // PS4-específico
    595: 'GQli4UAXTfQ',   // PS4-específico
    604: '7OpNDDNMJyo',   // PS4-específico
    606: 'O-hEvSnv2o4',   // PS4-específico
    612: 'nG-FYqFutUo',   // PS4-específico
    656: 'K7xiuldOPKw',   // PS4-específico
    659: 'P0jjY6bxakI',   // PS4-específico
    660: 'nTc+tFajGqQ',   // PS4-específico
    672: 'vpo3SbGFuEk',   // PS4-específico
};

// ── Referência de NIDs identificados ─────────────────────────
//
// libkernel_web — syscalls POSIX confirmados (FreeBSD 9.x):
//   syscall #20  (getpid)       NID=HoLVWNanBBc  RVA=0x2CB70
//   syscall #73  (munmap)       NID=UqDGjXA5yUM  RVA=0x2B150  ← lk_munmap
//   syscall #202 (__sysctl)     NID=7NwggrWJ5cA  RVA=0x2D5A0
//   syscall #240 (nanosleep)    NID=NhpspxdjEKU  RVA=0x2D4C0  ← chamado por sleep
//   syscall #454 (_umtx_op)     NID=04AjkP0jO9U  RVA=0x2BAC0  ← worker_wait_return+0x0C
//
// libSceNKWebKit — exports de interesse:
//   NID -x5vK4NNNYM  RVA=0x00C87A20  → wk_vtable_first_element (WKDownloadGetTypeID)
//
// OFFSET_WORKER_STACK_OFFSET
//   [!] Offset dentro da struct pthread/kthread do ponteiro de stack
//       Requer análise do layout da struct ScePthread em libkernel
//       Estimativa baseada em FreeBSD 9 libthr: ~0x28 (campo td_kstack_pages)
//       TODO: analisar pthread_join e _umtx_op para confirmar
const OFFSET_WORKER_STACK_OFFSET = 0x0;
