#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdint.h>
#include <ctype.h>
#include <elf.h>
#include <pthread.h>
#include <regex.h>
#include <zlib.h>

#define SCANNER_VERSION "v10.1-NativeDEX"
#define MAX_API_ENTRIES 256
#define NUM_THREADS 8

enum PropertyApiType { API_TYPE_NONE = 0, API_TYPE_BOOL, API_TYPE_INT, API_TYPE_STR, API_TYPE_GENERIC };

typedef struct { uint64_t addr; int api_type; int key_reg; } ApiEntry;

typedef struct {
    uint64_t plt_start, plt_end;
    const uint8_t *data;
    size_t size;
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    const Elf64_Rela *relas_plt, *relas_dyn;
    size_t count_plt, count_dyn;
    const Elf64_Sym *syms;
    size_t sym_count;
    const char *dynstr;
    const Elf64_Sym *symtab;
    size_t symtab_count;
    const char *strtab;
    int has_property_api;
    ApiEntry prop_got[MAX_API_ENTRIES];
    size_t prop_got_cnt;
    ApiEntry prop_syms[MAX_API_ENTRIES];
    size_t prop_syms_cnt;
    uint64_t guard_got[MAX_API_ENTRIES];
    size_t guard_got_cnt;
    uint64_t dlsym_got, atexit_got;
    uint64_t memo_addr[16384];
    int16_t memo_val[16384];
} ElfContext;

typedef struct {
    const char *name;
    uint64_t vaddr, page;
    uint32_t offset;
    int status; // 1 = NOT_A_PROPERTY, 2 = RESOLVED
    int pat_idx;
    char res[128];
    uint64_t t_vaddr;
    uint64_t g_vaddr;
} PropQuery;

static inline int is_valid_range(const uint8_t *data, size_t size, const void *ptr, size_t len) {
    const uint8_t *p = (const uint8_t *)ptr;
    return (p >= data && p <= data + size && len <= (size_t)((data + size) - p));
}

static inline int is_valid_prop_str(ElfContext *ctx, const char *s, size_t max_len) {
    if (!s) return 0;
    const uint8_t *p = (const uint8_t *)s;
    if (p < ctx->data || p >= ctx->data + ctx->size) return 0;
    size_t avail = (size_t)((ctx->data + ctx->size) - p);
    if (max_len > avail) max_len = avail;
    if (max_len == 0) return 0;
    if (s[0] == '\0') return 1;
    size_t len = 0;
    while (len < max_len && s[len] != '\0') {
        if (s[len] == '%' || s[len] == '\n' || s[len] == '\r' || !isprint((unsigned char)s[len])) return 0;
        len++;
    }
    return (len < max_len && s[len] == '\0');
}

static const void* resolve_vaddr_bounded(ElfContext *ctx, uint64_t vaddr, size_t min_bytes) {
    for (int p = 0; p < ctx->ehdr->e_phnum; p++) {
        if (ctx->phdr[p].p_type == PT_LOAD && vaddr >= ctx->phdr[p].p_vaddr && vaddr < ctx->phdr[p].p_vaddr + ctx->phdr[p].p_filesz) {
            uint64_t rel = vaddr - ctx->phdr[p].p_vaddr;
            uint64_t offset = ctx->phdr[p].p_offset + rel;
            if (rel + min_bytes <= ctx->phdr[p].p_filesz && offset + min_bytes <= ctx->size) return ctx->data + offset;
            return NULL;
        }
    }
    return NULL;
}

static uint64_t file_offset_to_vaddr(Elf64_Ehdr *ehdr, Elf64_Phdr *phdr, uint64_t offset) {
    for (int p = 0; p < ehdr->e_phnum; p++) {
        if (phdr[p].p_type == PT_LOAD && offset >= phdr[p].p_offset && offset < phdr[p].p_offset + phdr[p].p_filesz)
            return phdr[p].p_vaddr + (offset - phdr[p].p_offset);
    }
    return offset;
}

static const char* get_sym_name(ElfContext *ctx, uint32_t sym_idx) {
    if (!ctx->syms || !ctx->dynstr) return NULL;
    if (ctx->sym_count > 0 && sym_idx >= ctx->sym_count) return NULL;
    const Elf64_Sym *sym = &ctx->syms[sym_idx];
    if (!is_valid_range(ctx->data, ctx->size, sym, sizeof(Elf64_Sym))) return NULL;
    const char *str = ctx->dynstr + sym->st_name;
    if (!is_valid_range(ctx->data, ctx->size, str, 1)) return NULL;
    size_t max_rem = (size_t)((ctx->data + ctx->size) - (const uint8_t *)str);
    return memchr(str, '\0', max_rem) ? str : NULL;
}

static inline int get_symbol_property_api_type(const char *name, int *out_key_reg) {
    if (!name) return API_TYPE_NONE;
    if (out_key_reg) *out_key_reg = 0;
    if (strstr(name, "VendorTag") || strstr(name, "Metadata") || strstr(name, "_ZN2C2") ||
        strstr(name, "PropertyMap") || strstr(name, "PropertyBag")) return API_TYPE_NONE;
    if (strstr(name, "CachedProperty") && strstr(name, "Get")) {
        if (out_key_reg) *out_key_reg = 1;
        return API_TYPE_STR;
    }
    if (strstr(name, "Logger") && strstr(name, "PropertyGet")) {
        if (out_key_reg) *out_key_reg = 1;
        return API_TYPE_STR;
    }
    if (strstr(name, "PropertyMonitor")) {
        if (out_key_reg) *out_key_reg = 0;
        return API_TYPE_GENERIC;
    }
    if (strstr(name, "perfGetProp")) {
        if (out_key_reg) *out_key_reg = 1;
        return API_TYPE_STR;
    }
    if (strstr(name, "PerfConfigDataStore") || strstr(name, "ServerConfigurableFlag")) {
        if (out_key_reg) *out_key_reg = 1;
        return API_TYPE_STR;
    }
    if (strstr(name, "limitProcessMemory")) {
        if (out_key_reg) *out_key_reg = 0;
        return API_TYPE_INT;
    }
    if (strstr(name, "GetBoolProperty") || strstr(name, "property_get_bool")) return API_TYPE_BOOL;
    if (strstr(name, "GetIntProperty") || strstr(name, "GetUintProperty") || strstr(name, "property_get_int")) return API_TYPE_INT;
    if (strstr(name, "GetProperty") || strstr(name, "PropertyGet") || strstr(name, "property_get") ||
        strstr(name, "GetProp") ||
        strstr(name, "__system_property_find") || strstr(name, "__system_property_read")) return API_TYPE_STR;
    if (strstr(name, "SetProperty") || strstr(name, "property_set") || strstr(name, "__system_property_set") ||
        strstr(name, "WaitForProperty")) return API_TYPE_GENERIC;
    if (strstr(name, "sysprop") || strstr(name, "system_properties") || strstr(name, "aconfig_storage")) return API_TYPE_GENERIC;
    return API_TYPE_NONE;
}

static inline int is_symbol_guard_or_cache(const char *name) {
    if (!name) return 0;
    return (strstr(name, "guard_release") || strstr(name, "guard_acquire") ||
            strstr(name, "call_once") || strstr(name, "pthread_once"));
}

static inline int is_string_copy_or_init_symbol(const char *name) {
    if (!name) return 0;
    return (strstr(name, "__init") || strstr(name, "memcpy") || strstr(name, "strcpy") ||
            strstr(name, "strlcpy") || strstr(name, "basic_string") || strstr(name, "assign"));
}

static inline int is_prologue_or_nop(uint32_t inst) {
    return (inst == 0xD503201F || inst == 0xD503245F || inst == 0xD50324DF || inst == 0xD503249F || inst == 0xD503233F || inst == 0xD503237F);
}

static void init_elf_context(ElfContext *ctx, const uint8_t *data, size_t size, Elf64_Ehdr *ehdr, Elf64_Phdr *phdr) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->data = data; ctx->size = size; ctx->ehdr = ehdr; ctx->phdr = phdr;

    if (ehdr->e_shoff != 0 && ehdr->e_shnum > 0 && ehdr->e_shstrndx < ehdr->e_shnum &&
        is_valid_range(data, size, data + ehdr->e_shoff, (size_t)ehdr->e_shnum * sizeof(Elf64_Shdr))) {
        Elf64_Shdr *shdr = (Elf64_Shdr *)(data + ehdr->e_shoff);
        if (is_valid_range(data, size, data + shdr[ehdr->e_shstrndx].sh_offset, shdr[ehdr->e_shstrndx].sh_size)) {
            const char *shstrtab = (const char *)(data + shdr[ehdr->e_shstrndx].sh_offset);
            size_t shstr_sz = shdr[ehdr->e_shstrndx].sh_size;
            for (int i = 0; i < ehdr->e_shnum; i++) {
                if (shdr[i].sh_name >= shstr_sz) continue;
                if (shdr[i].sh_type != SHT_NOBITS && !is_valid_range(data, size, data + shdr[i].sh_offset, shdr[i].sh_size)) continue;
                const char *name = shstrtab + shdr[i].sh_name;
                if (!strcmp(name, ".plt") || !strcmp(name, ".plt.sec") || !strcmp(name, ".plt.got")) {
                    if (ctx->plt_start == 0 || shdr[i].sh_addr < ctx->plt_start) ctx->plt_start = shdr[i].sh_addr;
                    if (shdr[i].sh_addr + shdr[i].sh_size > ctx->plt_end) ctx->plt_end = shdr[i].sh_addr + shdr[i].sh_size;
                } else if (!strcmp(name, ".rela.plt") && shdr[i].sh_type == SHT_RELA) {
                    ctx->relas_plt = (const Elf64_Rela *)(data + shdr[i].sh_offset);
                    ctx->count_plt = shdr[i].sh_size / sizeof(Elf64_Rela);
                } else if (!strcmp(name, ".rela.dyn") && shdr[i].sh_type == SHT_RELA) {
                    ctx->relas_dyn = (const Elf64_Rela *)(data + shdr[i].sh_offset);
                    ctx->count_dyn = shdr[i].sh_size / sizeof(Elf64_Rela);
                } else if (!strcmp(name, ".dynsym")) {
                    ctx->syms = (const Elf64_Sym *)(data + shdr[i].sh_offset);
                    ctx->sym_count = shdr[i].sh_size / sizeof(Elf64_Sym);
                } else if (!strcmp(name, ".dynstr")) {
                    ctx->dynstr = (const char *)(data + shdr[i].sh_offset);
                } else if (!strcmp(name, ".symtab")) {
                    ctx->symtab = (const Elf64_Sym *)(data + shdr[i].sh_offset);
                    ctx->symtab_count = shdr[i].sh_size / sizeof(Elf64_Sym);
                } else if (!strcmp(name, ".strtab")) {
                    ctx->strtab = (const char *)(data + shdr[i].sh_offset);
                }
            }
        }
    }

    if (!ctx->relas_plt || !ctx->syms || !ctx->dynstr) {
        for (int p = 0; p < ehdr->e_phnum; p++) {
            if (phdr[p].p_type != PT_DYNAMIC || !is_valid_range(data, size, data + phdr[p].p_offset, phdr[p].p_filesz)) continue;
            const Elf64_Dyn *dyn = (const Elf64_Dyn *)(data + phdr[p].p_offset);
            size_t dyn_count = phdr[p].p_filesz / sizeof(Elf64_Dyn);
            uint64_t jmprel_v = 0, rela_v = 0, sym_v = 0, str_v = 0, hash_v = 0, ghash_v = 0;
            size_t plt_sz = 0, rela_sz = 0, rela_ent = 0;
            for (size_t d = 0; d < dyn_count; d++) {
                if (dyn[d].d_tag == DT_JMPREL) jmprel_v = dyn[d].d_un.d_ptr;
                else if (dyn[d].d_tag == DT_PLTRELSZ) plt_sz = dyn[d].d_un.d_val;
                else if (dyn[d].d_tag == DT_RELA) rela_v = dyn[d].d_un.d_ptr;
                else if (dyn[d].d_tag == DT_RELASZ) rela_sz = dyn[d].d_un.d_val;
                else if (dyn[d].d_tag == DT_RELAENT) rela_ent = dyn[d].d_un.d_val;
                else if (dyn[d].d_tag == DT_SYMTAB) sym_v = dyn[d].d_un.d_ptr;
                else if (dyn[d].d_tag == DT_STRTAB) str_v = dyn[d].d_un.d_ptr;
                else if (dyn[d].d_tag == DT_HASH) hash_v = dyn[d].d_un.d_ptr;
                else if (dyn[d].d_tag == DT_GNU_HASH) ghash_v = dyn[d].d_un.d_ptr;
            }
            if (!ctx->relas_plt && jmprel_v && plt_sz >= sizeof(Elf64_Rela)) {
                const Elf64_Rela *ptr = (const Elf64_Rela *)resolve_vaddr_bounded(ctx, jmprel_v, plt_sz);
                if (ptr) { ctx->relas_plt = ptr; ctx->count_plt = plt_sz / sizeof(Elf64_Rela); }
            }
            if (!ctx->relas_dyn && rela_v && rela_sz >= sizeof(Elf64_Rela) && (!rela_ent || rela_ent == sizeof(Elf64_Rela))) {
                const Elf64_Rela *ptr = (const Elf64_Rela *)resolve_vaddr_bounded(ctx, rela_v, rela_sz);
                if (ptr && memcmp(ptr, "APS2", 4) != 0) { ctx->relas_dyn = ptr; ctx->count_dyn = rela_sz / sizeof(Elf64_Rela); }
            }
            if (!ctx->syms && sym_v) ctx->syms = (const Elf64_Sym *)resolve_vaddr_bounded(ctx, sym_v, sizeof(Elf64_Sym));
            if (!ctx->dynstr && str_v) ctx->dynstr = (const char *)resolve_vaddr_bounded(ctx, str_v, 1);
            if (ctx->sym_count == 0) {
                if (hash_v) {
                    const uint32_t *h = (const uint32_t *)resolve_vaddr_bounded(ctx, hash_v, 8);
                    if (h) ctx->sym_count = h[1];
                } else if (ghash_v) {
                    const uint32_t *gh = (const uint32_t *)resolve_vaddr_bounded(ctx, ghash_v, 16);
                    if (gh) {
                        uint32_t nbuckets = gh[0], symoffset = gh[1], bloom_sz = gh[2];
                        if (bloom_sz < 65536 && nbuckets < 1048576) {
                            const uint32_t *buckets = (const uint32_t *)((const Elf64_Addr *)(gh + 4) + bloom_sz);
                            if (is_valid_range(data, size, buckets, (size_t)nbuckets * 4)) {
                            uint32_t max_sym = 0;
                            for (uint32_t b = 0; b < nbuckets; b++) if (buckets[b] > max_sym) max_sym = buckets[b];
                            if (max_sym >= symoffset) {
                                const uint32_t *chains = buckets + nbuckets;
                                uint32_t idx = max_sym;
                                while (is_valid_range(data, size, &chains[idx - symoffset], 4)) {
                                    uint32_t cval = chains[idx++ - symoffset];
                                    if (cval & 1) break;
                                }
                                ctx->sym_count = idx;
                            } else if (symoffset > 0) ctx->sym_count = symoffset;
                        }
                        }
                    }
                }
            }
        }
    }

    if (ctx->syms && ctx->dynstr && ctx->sym_count > 0) {
        for (size_t s = 0; s < ctx->sym_count; s++) {
            const char *sname = get_sym_name(ctx, (uint32_t)s);
            int key_reg = 0;
            int type = get_symbol_property_api_type(sname, &key_reg);
            if (type != API_TYPE_NONE) {
                ctx->has_property_api = 1;
                if (ctx->syms[s].st_value && ctx->prop_syms_cnt < MAX_API_ENTRIES)
                    ctx->prop_syms[ctx->prop_syms_cnt++] = (ApiEntry){ctx->syms[s].st_value, type, key_reg};
            }
        }
    }
    if (ctx->relas_plt && ctx->syms && ctx->dynstr) {
        for (size_t r = 0; r < ctx->count_plt; r++) {
            if (!is_valid_range(data, size, &ctx->relas_plt[r], sizeof(Elf64_Rela))) break;
            const char *sname = get_sym_name(ctx, ELF64_R_SYM(ctx->relas_plt[r].r_info));
            if (!sname) continue;
            uint64_t got_off = ctx->relas_plt[r].r_offset;
            int key_reg = 0;
            int type = get_symbol_property_api_type(sname, &key_reg);
            if (type != API_TYPE_NONE) {
                ctx->has_property_api = 1;
                if (ctx->prop_got_cnt < MAX_API_ENTRIES) ctx->prop_got[ctx->prop_got_cnt++] = (ApiEntry){got_off, type, key_reg};
            } else if (is_symbol_guard_or_cache(sname) && ctx->guard_got_cnt < MAX_API_ENTRIES) {
                ctx->guard_got[ctx->guard_got_cnt++] = got_off;
            } else if (!strcmp(sname, "dlsym")) ctx->dlsym_got = got_off;
            else if (strstr(sname, "atexit")) ctx->atexit_got = got_off;
        }
    }
    if (ctx->relas_dyn && ctx->syms && ctx->dynstr) {
        for (size_t r = 0; r < ctx->count_dyn; r++) {
            if (!is_valid_range(data, size, &ctx->relas_dyn[r], sizeof(Elf64_Rela))) break;
            uint32_t sym_idx = ELF64_R_SYM(ctx->relas_dyn[r].r_info);
            if (!sym_idx) continue;
            const char *sname = get_sym_name(ctx, sym_idx);
            int key_reg = 0;
            int type = get_symbol_property_api_type(sname, &key_reg);
            if (type != API_TYPE_NONE) {
                ctx->has_property_api = 1;
                if (ctx->prop_got_cnt < MAX_API_ENTRIES) ctx->prop_got[ctx->prop_got_cnt++] = (ApiEntry){ctx->relas_dyn[r].r_offset, type, key_reg};
            }
        }
    }
}

static uint64_t extract_plt_got_target(ElfContext *ctx, uint64_t call_vaddr) {
    const uint32_t *code = (const uint32_t *)resolve_vaddr_bounded(ctx, call_vaddr, 24);
    if (!code) return 0;
    int idx = 0; uint64_t pc = call_vaddr;
    while (idx < 4 && is_prologue_or_nop(code[idx])) { idx++; pc += 4; }
    uint32_t i1 = code[idx], i2 = code[idx + 1];
    if ((i1 & 0x9F000000) == 0x90000000 && (i2 & 0xFFC00000) == 0xF9400000 && (i1 & 0x1F) == ((i2 >> 5) & 0x1F)) {
        int64_t imm = (int64_t)((((i1 >> 5) & 0x7FFFF) << 2) | ((i1 >> 29) & 0x3));
        if (imm & 0x100000) imm -= 0x200000;
        return ((pc & ~0xFFFULL) + (imm << 12)) + (((i2 >> 10) & 0xFFF) << 3);
    }
    return 0;
}

static int is_call_to_guard_api(ElfContext *ctx, uint64_t call_vaddr) {
    uint64_t got = extract_plt_got_target(ctx, call_vaddr);
    if (!got) return 0;
    for (size_t i = 0; i < ctx->guard_got_cnt; i++) if (ctx->guard_got[i] == got) return 1;
    return 0;
}

static const char *get_got_symbol_name(ElfContext *ctx, uint64_t got_off) {
    if (!ctx->dynstr || !ctx->syms) return NULL;
    if (ctx->relas_plt) {
        for (size_t r = 0; r < ctx->count_plt; r++) {
            if (ctx->relas_plt[r].r_offset == got_off) {
                return get_sym_name(ctx, ELF64_R_SYM(ctx->relas_plt[r].r_info));
            }
        }
    }
    if (ctx->relas_dyn) {
        for (size_t r = 0; r < ctx->count_dyn; r++) {
            if (ctx->relas_dyn[r].r_offset == got_off) {
                return get_sym_name(ctx, ELF64_R_SYM(ctx->relas_dyn[r].r_info));
            }
        }
    }
    return NULL;
}

static const char *get_vaddr_symbol_name(ElfContext *ctx, uint64_t vaddr) {
    if (vaddr >= ctx->plt_start && vaddr < ctx->plt_end) {
        uint64_t got = extract_plt_got_target(ctx, vaddr);
        if (got) return get_got_symbol_name(ctx, got);
    }
    if (ctx->syms && ctx->dynstr && ctx->sym_count > 0) {
        for (size_t s = 0; s < ctx->sym_count; s++) {
            if (ctx->syms[s].st_value == vaddr) {
                return get_sym_name(ctx, (uint32_t)s);
            }
        }
    }
    if (ctx->symtab && ctx->strtab && ctx->symtab_count > 0) {
        for (size_t s = 0; s < ctx->symtab_count; s++) {
            if (ctx->symtab[s].st_value == vaddr && ctx->symtab[s].st_name) {
                const char *sn = ctx->strtab + ctx->symtab[s].st_name;
                if (sn[0] && sn[0] != '$') return sn;
            }
        }
    }
    return NULL;
}

static inline int instruction_writes_reg(uint32_t inst, uint32_t *rd1, uint32_t *rd2) {
    *rd1 = 31; *rd2 = 31;
    // SIMD / Floating-point instructions write vector/FP registers (V0-V31), NOT general purpose X0-X30
    if ((inst & 0x0E000000) == 0x0E000000) return 0; // Advanced SIMD vector & scalar
    if ((inst & 0x5E000000) == 0x1E000000) return 0; // Floating point data processing
    if ((inst & 0x3E000000) == 0x2C000000) return 0; // SIMD LDP / STP
    if ((inst & 0x3B200000) == 0x3C000000) return 0; // SIMD LDR / STR
    if ((inst & 0x04000000) != 0 && ((inst & 0x0A000000) == 0x08000000 || (inst & 0x3A000000) == 0x28000000)) return 0; // Load/Store FP/SIMD (V bit = 1)

    if ((inst & 0xFC000000) == 0x14000000) return 0; // B
    if ((inst & 0xFC000000) == 0x94000000) { *rd1 = 30; return 1; } // BL writes LR (X30)
    if ((inst & 0xFE000000) == 0x54000000) return 0; // B.cond
    if ((inst & 0x7E000000) == 0x34000000) return 0; // CBZ / CBNZ
    if ((inst & 0x7E000000) == 0x36000000) return 0; // TBZ / TBNZ
    if ((inst & 0x3FE00000) == 0x3A400000) return 0; // CCMP / CCMN (conditional compare does not write registers)
    if ((inst & 0x3F200000) == 0x38800000 || (inst & 0xFF000000) == 0xD8000000) return 0; // PRFM / PRFUM
    if ((inst & 0xFFE00000) == 0xD5000000) return 0; // System instructions (MSR, NOP, HINT, BARRIER)
    if ((inst & 0xFE000000) == 0xD6000000) {
        if ((inst & 0xFFFFFC1F) == 0xD63F0000) { *rd1 = 30; return 1; } // BLR
        return 0; // BR, RET
    }
    if ((inst & 0x3A000000) == 0x28000000) {
        if (inst & 0x00400000) { // LDP
            *rd1 = inst & 0x1F;
            *rd2 = (inst >> 10) & 0x1F;
            return 1;
        }
        return 0; // STP
    }
    if ((inst & 0x0A000000) == 0x08000000) {
        if (inst & 0x00400000) { // LDR / LDUR
            *rd1 = inst & 0x1F;
            return 1;
        }
        return 0; // STR / STUR
    }
    uint32_t rd = inst & 0x1F;
    if (rd < 31) {
        *rd1 = rd;
        return 1;
    }
    return 0;
}

static int is_code_string_init(ElfContext *ctx, uint64_t call_vaddr) {
    const uint32_t *code = (const uint32_t *)resolve_vaddr_bounded(ctx, call_vaddr, 256);
    if (!code) return 0;
    for (size_t step = 0; step < 64; step++) {
        if (!is_valid_range(ctx->data, ctx->size, &code[step], 4)) break;
        uint32_t inst = code[step];
        if ((inst & 0xFFFFFC1F) == 0xD65F0000) break; // RET
        if ((inst & 0xFC000000) == 0x94000000) { // BL
            int32_t imm26 = inst & 0x03FFFFFF; if (imm26 & 0x02000000) imm26 -= 0x04000000;
            uint64_t tgt = call_vaddr + (step * 4) + (imm26 << 2);
            const char *tfn = get_vaddr_symbol_name(ctx, tgt);
            if (tfn && (strstr(tfn, "strlen") || strstr(tfn, "memmove") || strstr(tfn, "memcpy"))) return 1;
        }
    }
    return 0;
}

static inline int is_string_copy_or_init(ElfContext *ctx, uint64_t cv, const char *name) {
    if (name && is_string_copy_or_init_symbol(name)) return 1;
    if (cv && is_code_string_init(ctx, cv)) return 1;
    return 0;
}

static int is_call_to_property_api(ElfContext *ctx, uint64_t call_vaddr, int depth, int *out_api_type, uint32_t *out_key_mask) {
    if (depth > 4) return 0;
    uint32_t mh = (uint32_t)((call_vaddr >> 2) ^ (call_vaddr >> 8)) & 16383;
    const char *vname = get_vaddr_symbol_name(ctx, call_vaddr);
    if (vname && (strstr(vname, "WaitForProperty") || strstr(vname, "PropertyMonitor"))) {
        if (depth == 0) {
            ctx->memo_addr[mh] = call_vaddr; ctx->memo_val[mh] = API_TYPE_GENERIC;
            if (out_api_type) *out_api_type = API_TYPE_GENERIC;
            if (out_key_mask) *out_key_mask = 1;
            return 1;
        }
        return 0;
    }
    if (ctx->memo_addr[mh] == call_vaddr && ctx->memo_val[mh] != 0) {
        if (ctx->memo_val[mh] < 0) return 0;
        if (out_api_type) *out_api_type = ctx->memo_val[mh] & 0x0F;
        if (out_key_mask) *out_key_mask = ((uint16_t)ctx->memo_val[mh] >> 4) & 0xFF;
        return 1;
    }

    int local_type = API_TYPE_GENERIC;
    for (size_t s = 0; s < ctx->prop_syms_cnt; s++) {
        if (ctx->prop_syms[s].addr == call_vaddr) {
            local_type = ctx->prop_syms[s].api_type;
            uint32_t mask = (1 << ctx->prop_syms[s].key_reg);
            ctx->memo_addr[mh] = call_vaddr; ctx->memo_val[mh] = (int16_t)((mask << 4) | (local_type & 0x0F));
            if (out_api_type) *out_api_type = local_type;
            if (out_key_mask) *out_key_mask = mask;
            return 1;
        }
    }
    uint64_t got = extract_plt_got_target(ctx, call_vaddr);
    if (got) {
        for (size_t i = 0; i < ctx->prop_got_cnt; i++) {
            if (ctx->prop_got[i].addr == got) {
                local_type = ctx->prop_got[i].api_type;
                uint32_t mask = (1 << ctx->prop_got[i].key_reg);
                ctx->memo_addr[mh] = call_vaddr; ctx->memo_val[mh] = (int16_t)((mask << 4) | (local_type & 0x0F));
                if (out_api_type) *out_api_type = local_type;
                if (out_key_mask) *out_key_mask = mask;
                return 1;
            }
        }
        if (depth == 0) { ctx->memo_addr[mh] = call_vaddr; ctx->memo_val[mh] = -1; }
        return 0;
    }
    const uint32_t *code = (const uint32_t *)resolve_vaddr_bounded(ctx, call_vaddr, 4);
    if (!code) {
        if (depth == 0) { ctx->memo_addr[mh] = call_vaddr; ctx->memo_val[mh] = -1; }
        return 0;
    }

    int reg_src[32];
    for (int r = 0; r < 8; r++) reg_src[r] = r;
    for (int r = 8; r < 32; r++) reg_src[r] = -1;
    int stack_arg = -1;
    uint32_t collected_key_mask = 0;
    int final_type = API_TYPE_NONE;
    int has_int_conv = 0, has_bool_conv = 0;

    for (size_t step = 0; step < 64; step++) {
        if (!is_valid_range(ctx->data, ctx->size, &code[step], 4)) break;
        uint32_t sub = code[step];
        if ((sub & 0xFFFFFC1F) == 0xD65F0000 || (sub & 0xFFFFFC1F) == 0xD61F0000) break;

        // MOV Xd, Xm / MOV Wd, Wm
        if ((sub & 0xFFE0FFE0) == 0xAA0003E0 || (sub & 0xFFE0FFE0) == 0x2A0003E0) {
            uint32_t rd = sub & 0x1F;
            uint32_t rm = (sub >> 16) & 0x1F;
            reg_src[rd] = reg_src[rm];
            continue;
        }

        // ADD / SUB Xd, SP/X29, #imm (stack buffer reference)
        if (((sub & 0xFF800000) == 0x91000000) || ((sub & 0xFF800000) == 0xD1000000)) {
            uint32_t rd = sub & 0x1F;
            uint32_t rn = (sub >> 5) & 0x1F;
            if ((rn == 31 || rn == 29) && stack_arg >= 0) {
                reg_src[rd] = stack_arg;
                continue;
            }
        }

        // CSEL / CSINC Xd, Xn, Xm, cond
        if (((sub & 0xFFE00C00) == 0x9A800000) || ((sub & 0xFFE00C00) == 0x1A800000) ||
            ((sub & 0xFFE00C00) == 0x9A800400) || ((sub & 0xFFE00C00) == 0x1A800400)) {
            uint32_t rd = sub & 0x1F;
            uint32_t xn = (sub >> 5) & 0x1F;
            uint32_t xm = (sub >> 16) & 0x1F;
            if (reg_src[xn] >= 0) reg_src[rd] = reg_src[xn];
            else if (reg_src[xm] >= 0) reg_src[rd] = reg_src[xm];
            else reg_src[rd] = -1;
            continue;
        }

        // LDR Xd, [Xn, #imm]
        if ((sub & 0xFFC00000) == 0xF9400000) {
            uint32_t rd = sub & 0x1F;
            uint32_t xn = (sub >> 5) & 0x1F;
            if (reg_src[xn] >= 0) reg_src[rd] = reg_src[xn];
            else reg_src[rd] = -1;
            continue;
        }

        // B.cond / CBZ / CBNZ / TBZ / TBNZ: conditional forward branch over guard/error block
        int is_b_cond = ((sub & 0xFF000010) == 0x54000000);
        int is_cbz = ((sub & 0x7E000000) == 0x34000000);
        int is_tbz = ((sub & 0x7E000000) == 0x36000000);
        if (is_b_cond || is_cbz || is_tbz) {
            int32_t c_simm = 0;
            if (is_b_cond || is_cbz) {
                c_simm = (int32_t)((sub >> 5) & 0x7FFFF);
                if (c_simm & 0x40000) c_simm -= 0x80000;
            } else {
                c_simm = (int32_t)((sub >> 5) & 0x3FFF);
                if (c_simm & 0x2000) c_simm -= 0x4000;
            }
            if (c_simm > 1 && (step + c_simm) < 64) {
                // If the block before the target terminates in an unconditional branch (B) or return (RET)
                uint32_t end_insn = code[step + c_simm - 1];
                if ((end_insn & 0xFC000000) == 0x14000000 || (end_insn & 0xFFFFFC1F) == 0xD65F0000) {
                    step += (c_simm - 1);
                    continue;
                }
            }
        }

        // Call (BL) or Tail Call (B)
        if ((sub & 0xFC000000) == 0x94000000 || (sub & 0xFC000000) == 0x14000000) {
            int is_uncond_b = ((sub & 0xFC000000) == 0x14000000);
            int32_t simm = sub & 0x03FFFFFF;
            if (simm & 0x02000000) simm -= 0x04000000;
            uint64_t nested = call_vaddr + (step * 4) + (simm << 2);
            uint64_t ngot = extract_plt_got_target(ctx, nested);
            if (ngot && ctx->dlsym_got && ngot == ctx->dlsym_got) {
                uint64_t x1_page = 0, x1_vaddr = 0;
                for (size_t prev = (step >= 8 ? step - 8 : 0); prev < step; prev++) {
                    uint32_t pi = code[prev];
                    if ((pi & 0x9F000000) == 0x90000000 && (pi & 0x1F) == 1) {
                        int64_t m = (int64_t)((((pi >> 5) & 0x7FFFF) << 2) | ((pi >> 29) & 0x3));
                        if (m & 0x100000) m -= 0x200000;
                        x1_page = ((call_vaddr + prev * 4) & ~0xFFFULL) + (m << 12);
                    } else if ((pi & 0xFF800000) == 0x91000000 && (pi & 0x1F) == 1 && ((pi >> 5) & 0x1F) == 1 && x1_page) {
                        x1_vaddr = x1_page + ((pi >> 10) & 0xFFF);
                    }
                }
                if (x1_vaddr) {
                    const char *sreq = (const char *)resolve_vaddr_bounded(ctx, x1_vaddr, 1);
                    if (is_valid_prop_str(ctx, sreq, 128)) {
                        int key_reg = 0;
                        int type = get_symbol_property_api_type(sreq, &key_reg);
                        if (type != API_TYPE_NONE) {
                            int caller_key_reg = (reg_src[key_reg] >= 0 && reg_src[key_reg] <= 7) ? reg_src[key_reg] : 0;
                            collected_key_mask |= (1 << caller_key_reg);
                            if (final_type == API_TYPE_NONE) final_type = type;
                        }
                    }
                }
            }
            int nested_type = API_TYPE_NONE;
            uint32_t nested_key_mask = 0;
            if (is_call_to_property_api(ctx, nested, depth + 1, &nested_type, &nested_key_mask)) {
                for (int r = 0; r <= 7; r++) {
                    if (nested_key_mask & (1 << r)) {
                        int caller_key_reg = reg_src[r];
                        if (caller_key_reg >= 0 && caller_key_reg <= 7) {
                            collected_key_mask |= (1 << caller_key_reg);
                        }
                    }
                }
                if (collected_key_mask && final_type == API_TYPE_NONE) {
                    final_type = nested_type;
                }
            }

            if (is_uncond_b) {
                if (simm > 0 && (step + simm) < 64) {
                    step += (simm - 1);
                    continue;
                }
                break;
            }

            const char *fn = get_vaddr_symbol_name(ctx, nested);
            
            if (fn && strstr(fn, "__system_property_wait")) {
                continue;
            }
            if (fn) {
                if (strstr(fn, "strtol") || strstr(fn, "atoi") || strstr(fn, "strtoll") || strstr(fn, "strtoul") || strstr(fn, "atol")) {
                    has_int_conv = 1;
                }
            }
            if (nested_type == API_TYPE_INT) has_int_conv = 1;
            else if (nested_type == API_TYPE_BOOL) has_bool_conv = 1;

            if (fn && is_symbol_guard_or_cache(fn)) continue;
            if (is_string_copy_or_init(ctx, nested, fn)) {
                if (reg_src[1] >= 0 && reg_src[1] <= 7) stack_arg = reg_src[1];
                continue;
            }
            if (fn && strstr(fn, "getenv")) {
                if (step + 1 < 64) {
                    uint32_t next_sub = code[step + 1];
                    if ((next_sub & 0x7F00001F) == 0x34000000) { // cbz x0, target
                        int32_t simm_cbz = (next_sub >> 5) & 0x7FFFF;
                        if (simm_cbz & 0x40000) simm_cbz -= 0x80000;
                        if (simm_cbz > 0 && (step + 1 + simm_cbz) < 64) {
                            step = step + simm_cbz;
                            continue;
                        }
                    }
                }
            }
            if (fn && (strstr(fn, "strlen") || strstr(fn, "_Zn") || strstr(fn, "_Zd") || strstr(fn, "alloc") || strstr(fn, "free"))) continue;

            // Промежуточный вызов разрушает caller-saved регистры X0-X18 и LR
            for (int r = 0; r <= 18; r++) reg_src[r] = -1;
            reg_src[30] = -1;
            continue;
        }

        uint32_t w1 = 31, w2 = 31;
        if (instruction_writes_reg(sub, &w1, &w2)) {
            if (w1 < 32) reg_src[w1] = -1;
            if (w2 < 32) reg_src[w2] = -1;
        }
    }
    if (collected_key_mask != 0) {
        if (final_type == API_TYPE_STR || final_type == API_TYPE_GENERIC) {
            if (has_int_conv) final_type = API_TYPE_INT;
            else if (has_bool_conv) final_type = API_TYPE_BOOL;
        }
        ctx->memo_addr[mh] = call_vaddr;
        ctx->memo_val[mh] = (int16_t)((collected_key_mask << 4) | (final_type & 0x0F));
        if (out_api_type) *out_api_type = final_type;
        if (out_key_mask) *out_key_mask = collected_key_mask;
        return 1;
    }
    if (depth == 0) {
        ctx->memo_addr[mh] = call_vaddr; ctx->memo_val[mh] = -1;
    }
    return 0;
}

static int is_virtual_property_call(ElfContext *ctx, const uint32_t *insts, size_t cnt, uint64_t seg_v, size_t add_idx, size_t k, uint32_t preg, uint32_t blr_rn) {
    size_t blr_idx = add_idx + k;
    // В виртуальном вызове (this->GetProperty(key, &val)) X0 — это this, поэтому имя свойства строго в X1 (preg == 1)
    if (blr_idx >= cnt || preg != 1 || k > 16) return 0;
    int has_stack_out_arg = 0;
    for (size_t s = 1; s < k; s++) {
        uint32_t m = insts[add_idx + s];
        if ((m & 0xFFFFFC1F) == 0xD65F0000 || (m & 0xFC000000) == 0x94000000 || (m & 0xFFFFFC1F) == 0xD63F0000) return 0;
        int br = ((m & 0x7C000000) == 0x14000000 || (m & 0x7E000000) == 0x34000000 || (m & 0x7E000000) == 0x36000000);
        int st = ((m & 0x3B000000) == 0x38000000 || (m & 0x3B000000) == 0x39000000);
        if (!br && !st && (m & 0x1F) == preg) return 0;
        // ADD / SUB / MOV X2, SP/X29/X19-X28/X0 (передача указателя &val в 3-м аргументе X2)
        uint32_t rd = m & 0x1F;
        uint32_t rn = (m >> 5) & 0x1F;
        if (rd == 2 && (rn == 31 || rn == 29 || (rn >= 19 && rn <= 28) || rn == 0)) {
            if ((m & 0xFF800000) == 0x91000000 || (m & 0xFF800000) == 0xD1000000 || (m & 0x7FE003E0) == 0x2A0003E0) {
                has_stack_out_arg = 1;
            }
        }
    }
    // Поиск подготовки указателя X2 назад (до 8 инструкций до ADRP/ADD X1)
    if (!has_stack_out_arg) {
        size_t b_start = add_idx > 8 ? add_idx - 8 : 0;
        for (size_t s = add_idx; s > b_start; s--) {
            uint32_t m = insts[s - 1];
            if ((m & 0xFFFFFC1F) == 0xD65F0000 || (m & 0xFC000000) == 0x94000000 || (m & 0xFFFFFC1F) == 0xD63F0000) break;
            uint32_t rd = m & 0x1F;
            uint32_t rn = (m >> 5) & 0x1F;
            if (rd == 2 && (rn == 31 || rn == 29 || (rn >= 19 && rn <= 28) || rn == 0)) {
                if ((m & 0xFF800000) == 0x91000000 || (m & 0xFF800000) == 0xD1000000 || (m & 0x7FE003E0) == 0x2A0003E0) {
                    has_stack_out_arg = 1;
                    break;
                }
            }
        }
    }
    int vload = 0;
    for (size_t b = 1; b <= 4 && blr_idx >= b; b++) {
        if ((insts[blr_idx - b] & 0xFFC00000) == 0xF9400000 && (insts[blr_idx - b] & 0x1F) == blr_rn) { vload = 1; break; }
    }
    if (!vload) return 0;
    for (size_t a = 1; a <= 10 && (blr_idx + a) < cnt; a++) {
        uint32_t post = insts[blr_idx + a];
        if ((post & 0xFFFFFC1F) == 0xD65F0000) break;
        if ((post & 0xFC000000) == 0x94000000) {
            int32_t s26 = post & 0x03FFFFFF; if (s26 & 0x02000000) s26 -= 0x04000000;
            if (is_call_to_guard_api(ctx, seg_v + ((blr_idx + a) * 4) + (s26 << 2))) return 1;
        }
    }
    return (has_stack_out_arg && ctx->has_property_api);
}

static int is_ptr_in_metadata_symbol(ElfContext *ctx, uint64_t ptr_vaddr) {
    if (!ctx->syms || !ctx->dynstr || !ctx->sym_count) return 0;
    for (size_t s = 0; s < ctx->sym_count; s++) {
        if (!is_valid_range(ctx->data, ctx->size, &ctx->syms[s], sizeof(Elf64_Sym))) break;
        uint64_t val = ctx->syms[s].st_value, sz = ctx->syms[s].st_size ? ctx->syms[s].st_size : 8;
        if (ptr_vaddr >= val && ptr_vaddr < val + sz) {
            const char *n = get_sym_name(ctx, (uint32_t)s);
            if (n && (strstr(n, "10descriptorE") || (strstr(n, "descriptor") && (strstr(n, "_ZN") || strstr(n, "aidl") || strstr(n, "android"))) ||
                strstr(n, "_ZTI") || strstr(n, "_ZTS") || strstr(n, "_ZTV") || strstr(n, "_ZTC") || strstr(n, "_ZTT"))) return 1;
        }
    }
    return 0;
}

static int is_aidl_or_type_descriptor(const char *s) {
    if (!s || (strncmp(s, "vendor.", 7) && strncmp(s, "android.", 8) && strncmp(s, "aidl.", 5))) return 0;
    const char *dot = strrchr(s, '.'); if (!dot) return 0;
    const char *leaf = dot + 1; size_t len = strlen(leaf); if (len < 2) return 0;
    if (leaf[0] == 'I' && isupper((unsigned char)leaf[1])) return 1;
    if (leaf[0] == 'B' && (leaf[1] == 'p' || leaf[1] == 'n') && isupper((unsigned char)leaf[2])) return 1;
    if (isupper((unsigned char)leaf[0])) {
        int low = 0;
        for (size_t i = 1; i < len; i++) {
            if (islower((unsigned char)leaf[i])) low = 1;
            else if (isupper((unsigned char)leaf[i]) && low) return 1;
        }
    }
    return 0;
}

static int is_candidate_prop_syntax(const char *s, size_t len) {
    // Чистая грамматика Bionic AOSP: длина 3..91, первый символ латинский, последний - буквенно-цифровой
    if (len < 3 || len > 91 || s[0] < 'a' || s[0] > 'z') return 0;
    if (!isalnum((unsigned char)s[len - 1])) return 0;
    if (len >= 3 && !strcmp(s + len - 3, ".so")) return 0;


    int dots = 0, seg_len = 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c == '.') {
            if (seg_len == 0) return 0; // Запрет пустых сегментов и двойных точек ".."
            dots++;
            seg_len = 0;
        } else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || (dots > 0 && c >= 'A' && c <= 'Z')) {
            seg_len++;
        } else {
            return 0; // Недопустимый символ по стандарту Bionic
        }
    }
    return (dots >= 1 && seg_len >= 1);
}

static void analyze_call_site(ElfContext *ctx, const uint32_t *insts, size_t cnt, uint64_t seg_v, size_t i, size_t add_idx, uint32_t preg, PropQuery *q) {
    size_t bl_idx = 0; int is_vcall = 0, api_type = API_TYPE_NONE, mid_call_cnt = 0, sso_copied = 0;
    int is_prop_get_3arg = 0;
    uint32_t cur_reg = preg;
    uint64_t reg_adr[32] = {0};
    uint32_t call_key_mask = 0;

    for (size_t k = 1; k <= 256 && (add_idx + k) < cnt; k++) {
        uint32_t cand = insts[add_idx + k];

        // 1. Границы функций ARM64 (эпилог/возврат/хвостовой вызов)
        if ((cand & 0xFFFFFC1F) == 0xD65F0000) break; // RET
        if (cand == 0xD69F03E0) break; // ERET
        if (cand == 0xD50323BF || cand == 0xD50323FF) break; // AUTIASP / AUTIBSP (epilogue)

        // 2. Начало следующей функции ARM64 (пролог)
        if (cand == 0xD503233F || cand == 0xD503237F) break; // PACIASP / PACIBSP (prologue)

        // Отслеживаем чтение байт строки из cur_reg (векторизованное копирование Clang SSO std::string: LDR/LDP/LDUR)
        uint32_t rn = (cand >> 5) & 0x1F;
        if (rn == cur_reg) {
            uint32_t opc = cand & 0xFFC00000;
            if (opc == 0x3DC00000 || opc == 0x3CC00000 || opc == 0x3C400000 ||
                opc == 0xF9400000 || opc == 0xB9400000 || opc == 0xF8400000 || opc == 0xB8400000 ||
                opc == 0xAD400000 || opc == 0x6D400000 || opc == 0xA9400000 || opc == 0x29400000) {
                sso_copied = 1;
            }
        }

        // Отслеживаем вычисление адресов глобальных переменных (ADR / ADRP + ADD)
        if ((cand & 0x9F000000) == 0x10000000) { // ADR Rd, #imm21
            int64_t imm21 = (int64_t)((((cand >> 5) & 0x7FFFF) << 2) | ((cand >> 29) & 0x3));
            if (imm21 & 0x100000) imm21 -= 0x200000;
            reg_adr[cand & 0x1F] = (seg_v + (add_idx + k) * 4) + imm21;
        } else if ((cand & 0x9F000000) == 0x90000000) { // ADRP Rd, #imm
            int64_t imm = (int64_t)((((cand >> 5) & 0x7FFFF) << 2) | ((cand >> 29) & 0x3));
            if (imm & 0x100000) imm -= 0x200000;
            reg_adr[cand & 0x1F] = ((seg_v + (add_idx + k) * 4) & ~0xFFFULL) + (imm * 4096);
        } else if ((cand & 0xFF800000) == 0x91000000) { // ADD Rd, Rn, #imm12
            uint32_t rn_add = (cand >> 5) & 0x1F;
            if (reg_adr[rn_add] != 0) reg_adr[cand & 0x1F] = reg_adr[rn_add] + ((cand >> 10) & 0xFFF);
        }

        // Если байты строки скопированы в глобальную переменную (статический конструктор std::string)
        uint32_t opc_st = cand & 0xFFC00000;
        if (sso_copied && !q->g_vaddr && rn != 31 && reg_adr[rn] != 0) {
            if (opc_st == 0xF9000000 || opc_st == 0xB9000000 || opc_st == 0xF8000000 ||
                opc_st == 0x3D800000 || opc_st == 0xA9000000 || opc_st == 0x29000000) {
                q->g_vaddr = reg_adr[rn];
            }
        }

        // CSEL Xd, Xn, Xm, cond
        if (((cand & 0xFFE00C00) == 0x9A800000) || ((cand & 0xFFE00C00) == 0x1A800000)) {
            uint32_t rd = cand & 0x1F;
            uint32_t xn = (cand >> 5) & 0x1F;
            uint32_t xm = (cand >> 16) & 0x1F;
            if (cur_reg == xn || cur_reg == xm) {
                cur_reg = rd;
                continue;
            }
        }

        // Отслеживаем передачу аргумента: MOV Xd, Xn / MOV Wd, Wn / ORR Xd, XZR, Xn
        if ((cand & 0xFFE0FFE0) == 0xAA0003E0 || (cand & 0xFFE0FFE0) == 0x2A0003E0) {
            uint32_t rm = (cand >> 16) & 0x1F;
            uint32_t rd = cand & 0x1F;
            if (rm == cur_reg) {
                cur_reg = rd;
                continue;
            }
        }

        if ((cand & 0xFC000000) == 0x94000000 || (cand & 0xFC000000) == 0x14000000) {
            int is_uncond_b = ((cand & 0xFC000000) == 0x14000000);
            int32_t imm26 = cand & 0x03FFFFFF; if (imm26 & 0x02000000) imm26 -= 0x04000000;
            uint64_t cv = seg_v + ((add_idx + k) * 4) + (imm26 << 2);
            call_key_mask = 0;
            if (is_call_to_property_api(ctx, cv, 0, &api_type, &call_key_mask)) {
                int k_reg = 0;
                while (k_reg < 8 && ((call_key_mask & (1 << k_reg)) == 0)) k_reg++;
                if (k_reg < 8) {
                    uint64_t key_vaddr = 0;
                    for (size_t b = 1; b <= 48 && (add_idx + k) >= b; b++) {
                        size_t b_idx = add_idx + k - b;
                        uint32_t bi = insts[b_idx];
                        if ((bi & 0x9F000000) == 0x10000000 && (bi & 0x1F) == k_reg) {
                            int64_t m = (int64_t)((((bi >> 5) & 0x7FFFF) << 2) | ((bi >> 29) & 0x3));
                            if (m & 0x100000) m -= 0x200000;
                            key_vaddr = (seg_v + b_idx * 4) + m;
                            break;
                        }
                        if ((bi & 0xFF800000) == 0x91000000 && (bi & 0x1F) == k_reg) {
                            uint32_t rn = (bi >> 5) & 0x1F;
                            uint32_t imm12 = (bi >> 10) & 0xFFF;
                            if (rn == 31 || rn == 29) break;
                            for (size_t bb = 1; bb <= 8 && b_idx >= bb; bb++) {
                                uint32_t pbi = insts[b_idx - bb];
                                if ((pbi & 0x9F000000) == 0x90000000 && (pbi & 0x1F) == rn) {
                                    int64_t m = (int64_t)((((pbi >> 5) & 0x7FFFF) << 2) | ((pbi >> 29) & 0x3));
                                    if (m & 0x100000) m -= 0x200000;
                                    key_vaddr = (((seg_v + (b_idx - bb) * 4) & ~0xFFFULL) + (m << 12)) + imm12;
                                    break;
                                }
                                uint32_t w1 = 31, w2 = 31;
                                if (instruction_writes_reg(pbi, &w1, &w2) && (w1 == rn || w2 == rn)) break;
                            }
                            break;
                        }
                        if ((bi & 0xFC000000) == 0x94000000 || (bi & 0xFFFFFC1F) == 0xD65F0000) break;
                    }
                    if (key_vaddr != 0 && key_vaddr != q->vaddr && (q->g_vaddr == 0 || key_vaddr != q->g_vaddr) && (q->t_vaddr == 0 || key_vaddr != q->t_vaddr)) {
                        if (++mid_call_cnt > 6) break;
                        continue;
                    }
                }
                if (((call_key_mask & (1 << cur_reg)) != 0) || sso_copied || cur_reg >= 19) {
                    bl_idx = add_idx + k;
                    const char *sfn = get_vaddr_symbol_name(ctx, cv);
                    if (sfn && strstr(sfn, "property_get") && !strstr(sfn, "__system_property_get") && !strstr(sfn, "property_get_bool") && !strstr(sfn, "property_get_int")) {
                        is_prop_get_3arg = 1;
                    }
                    break;
                }
                if (cur_reg <= 18 && !sso_copied) break;
                if (++mid_call_cnt > 6) break;
                continue;
            }
            if (is_uncond_b) {
                // Если переход B ведет в PLT (хвостовой вызов tail-call) или назад, функция/ветка завершена
                if (ctx->plt_start && cv >= ctx->plt_start && cv < ctx->plt_end) break;
                if (imm26 <= 0) break;
                if (imm26 <= 256 && (add_idx + k + imm26) < cnt) {
                    k += (imm26 - 1);
                    continue;
                }
                break;
            }
            const char *fn = get_vaddr_symbol_name(ctx, cv);
            if (fn && is_symbol_guard_or_cache(fn)) continue;
            if (is_string_copy_or_init(ctx, cv, fn)) {
                sso_copied = 1;
                continue;
            }
            if (fn && (strstr(fn, "strlen") || strstr(fn, "_Zn") || strstr(fn, "_Zd") || strstr(fn, "alloc") || strstr(fn, "free"))) continue;

            if (cur_reg <= 18 && !sso_copied) break;
            if (++mid_call_cnt > 6) break;
            continue;
        } else if ((cand & 0xFFFFFC1F) == 0xD63F0000) {
            if (is_virtual_property_call(ctx, insts, cnt, seg_v, add_idx, k, cur_reg, (cand >> 5) & 0x1F)) {
                bl_idx = add_idx + k; is_vcall = 1; break;
            }
            if (cur_reg <= 18 && !sso_copied) break;
            if (++mid_call_cnt > 6) break;
            continue;
        }

        uint32_t w1 = 31, w2 = 31;
        if (instruction_writes_reg(cand, &w1, &w2)) {
            if (!sso_copied && (w1 == cur_reg || w2 == cur_reg)) {
                break;
            }
        }
    }
    if (!bl_idx) return;
    
    q->status = 2;
    if (is_vcall) {
        // Qualcomm SDM / HAL GetProperty(this, key, &val): check if slot &val in X2 was pre-initialized
        int slot_base = -1; // 31 for SP, 29 for FP (X29)
        int slot_off = 0;
        int found_x2 = 0;

        // Scan backwards from bl_idx (up to 16 instructions) to find preparation of X2
        for (size_t s = 1; s <= 16 && bl_idx >= s; s++) {
            uint32_t m = insts[bl_idx - s];
            // ADD X2, SP/X29, #imm12
            if ((m & 0xFF8003FF) == 0x910003E2) {
                uint32_t rn = (m >> 5) & 0x1F;
                slot_base = rn;
                slot_off = (int)((m >> 10) & 0xFFF);
                found_x2 = 1;
                break;
            }
            // SUB X2, X29, #imm12
            else if ((m & 0xFF8003FF) == 0xD10003A2) {
                slot_base = 29;
                slot_off = -((int)((m >> 10) & 0xFFF));
                found_x2 = 1;
                break;
            }
            // MOV X2, Xn (2A0003E2 / AA0003E2)
            else if ((m & 0x7FE003FF) == 0x2A0003E2) {
                uint32_t rn = (m >> 5) & 0x1F;
                if (rn == 31) { slot_base = 31; slot_off = 0; found_x2 = 1; break; }
                for (size_t t = s + 1; t <= 24 && bl_idx >= t; t++) {
                    uint32_t tm = insts[bl_idx - t];
                    if ((tm & 0x1F) == rn) {
                        if ((tm & 0xFF800000) == 0x91000000) {
                            slot_base = (tm >> 5) & 0x1F;
                            slot_off = (int)((tm >> 10) & 0xFFF);
                            found_x2 = 1;
                        } else if ((tm & 0xFF800000) == 0xD1000000) {
                            slot_base = (tm >> 5) & 0x1F;
                            slot_off = -((int)((tm >> 10) & 0xFFF));
                            found_x2 = 1;
                        }
                        break;
                    }
                }
                if (found_x2) break;
            }
        }

        if (found_x2 && (slot_base == 31 || slot_base == 29)) {
            // Find store to that slot before the call (look backwards up to 32 instructions)
            for (size_t s = 1; s <= 32 && bl_idx >= s; s++) {
                size_t st_idx = bl_idx - s;
                uint32_t m = insts[st_idx];
                int match_store = 0;
                uint32_t rt = 31;

                if (slot_base == 31) { // SP
                    // STR Wt, [SP, #imm12] (B9000000 | ... | SP)
                    if ((m & 0xFFC00000) == 0xB9000000 && ((m >> 5) & 0x1F) == 31) {
                        int imm12 = (int)(((m >> 10) & 0xFFF) << 2);
                        if (imm12 == slot_off) {
                            match_store = 1;
                            rt = m & 0x1F;
                        }
                    }
                } else if (slot_base == 29) { // X29 (FP)
                    // STUR Wt, [X29, #simm9] (B8000000 | ... | X29)
                    if ((m & 0xFFC00C00) == 0xB8000000 && ((m >> 5) & 0x1F) == 29) {
                        int imm9 = (m >> 12) & 0x1FF;
                        if (imm9 & 0x100) imm9 -= 0x200;
                        if (imm9 == slot_off) {
                            match_store = 1;
                            rt = m & 0x1F;
                        }
                    }
                    // STR Wt, [X29, #imm12] (if positive offset)
                    else if ((m & 0xFFC00000) == 0xB9000000 && ((m >> 5) & 0x1F) == 29) {
                        int imm12 = (int)(((m >> 10) & 0xFFF) << 2);
                        if (imm12 == slot_off) {
                            match_store = 1;
                            rt = m & 0x1F;
                        }
                    }
                }

                if (match_store) {
                    if (rt == 31) { // WZR / XZR
                        strcpy(q->res, "DEFAULT_FALSE");
                        return;
                    } else {
                        // Find where rt was assigned before this store (up to 16 instructions back)
                        for (size_t rk = 1; rk <= 16 && st_idx >= rk; rk++) {
                            uint32_t ri = insts[st_idx - rk];
                            // MOV Wt, #imm16 or MOV Xt, #imm16
                            if ((ri & 0xFF80001F) == (0x52800000 | rt) || (ri & 0xFF80001F) == (0xD2800000 | rt)) {
                                uint32_t hw = (ri >> 21) & 0x3;
                                uint64_t imm16 = (ri >> 5) & 0xFFFF;
                                uint64_t val = imm16 << (hw * 16);
                                if (val == 0) {
                                    strcpy(q->res, "DEFAULT_FALSE");
                                } else if (val == 1) {
                                    int is_bool = 0;
                                    for (size_t p = 1; p <= 6 && (bl_idx + p) < cnt; p++) {
                                        uint32_t pi = insts[bl_idx + p];
                                        if ((pi & 0xFFFFFC1F) == 0xD65F0000) break;
                                        if ((pi & 0xFFE00000) == 0x71000000 && ((pi >> 10) & 0xFFF) == 1) { is_bool = 1; break; }
                                    }
                                    strcpy(q->res, is_bool ? "DEFAULT_TRUE" : "DEFAULT_INT: 1");
                                } else {
                                    snprintf(q->res, sizeof(q->res), "DEFAULT_INT: %llu", (unsigned long long)val);
                                }
                                return;
                            }
                            // MOV Wt, WZR / XZR
                            else if ((ri & 0xFFFFFFE0) == 0x2A1F03E0 || (ri & 0xFFFFFFE0) == 0xAA1F03E0) {
                                if ((ri & 0x1F) == rt) {
                                    strcpy(q->res, "DEFAULT_FALSE");
                                    return;
                                }
                            }
                        }
                    }
                    break;
                }
            }
        }
        if (!q->res[0] || !strcmp(q->res, "NOT_A_PROPERTY")) strcpy(q->res, "DYNAMIC_DEFAULT");
        return;
    }

    int64_t r_int[32] = {0}; int has_int[32] = {0}, has_v[32] = {0}; uint64_t r_page[32] = {0}, r_v[32] = {0}, r_v_alt[32] = {0};
    int reg_stk_base[32] = {0}, reg_stk_off[32] = {0};
    int slot_stk_base = 0, slot_stk_off = 0; uint64_t slot_v = 0;
    int had_mid_bl = 0;
    size_t scan_start = (i >= 96) ? i - 96 : 0;
    for (size_t k = scan_start; k < bl_idx; k++) {
        uint32_t cur = insts[k], rd = cur & 0x1F;
        if (k > add_idx && ((cur & 0xFC000000) == 0x94000000 || (cur & 0xFFFFFC1F) == 0xD63F0000)) {
            // Если перед вызовом GetProperty был промежуточный вызов конструктора std::string,
            // проверяем, не инициализировался ли stack slot (&this в X0) строкой из X1/X2
            if (reg_stk_base[0] != 0 && has_v[1]) {
                slot_stk_base = reg_stk_base[0];
                slot_stk_off = reg_stk_off[0];
                slot_v = r_v[1];
            } else if (reg_stk_base[0] != 0 && has_v[2]) {
                slot_stk_base = reg_stk_base[0];
                slot_stk_off = reg_stk_off[0];
                slot_v = r_v[2];
            }
            // Сбрасываем только X0 (this/ret), сохраняя подготовленные W1/W2 значения дефолта
            has_int[0] = 0; has_v[0] = 0; r_v_alt[0] = 0; r_page[0] = 0; reg_stk_base[0] = 0; reg_stk_off[0] = 0;
            had_mid_bl = 1;
            continue;
        }
        if (k < add_idx && ((cur & 0xFC000000) == 0x94000000 || (cur & 0xFFFFFC1F) == 0xD63F0000)) {
            // Если перед свойством был BL, сбрасываем caller-saved регистры X0-X18, сохраняя callee-saved X19-X28
            int is_chained_prop = 0;
            int saved_has_int = 0, saved_has_v = 0;
            int64_t saved_r_int = 0;
            uint64_t saved_r_v = 0, saved_r_page = 0;
            if ((cur & 0xFC000000) == 0x94000000) {
                int32_t imm26 = cur & 0x03FFFFFF;
                if (imm26 & 0x02000000) imm26 -= 0x04000000;
                uint64_t cv = seg_v + (k * 4) + (imm26 << 2);
                int p_type = 0;
                uint32_t p_mask = 0;
                if (is_call_to_property_api(ctx, cv, 0, &p_type, &p_mask)) {
                    is_chained_prop = 1;
                    int def_r = (has_int[1] || has_v[1]) ? 1 : ((has_int[2] || has_v[2]) ? 2 : 0);
                    if (def_r) {
                        saved_has_int = has_int[def_r];
                        saved_r_int = r_int[def_r];
                        saved_has_v = has_v[def_r];
                        saved_r_v = r_v[def_r];
                        saved_r_page = r_page[def_r];
                    }
                }
            }
            for (int r = 0; r <= 18; r++) { has_int[r] = 0; has_v[r] = 0; r_v_alt[r] = 0; r_page[r] = 0; reg_stk_base[r] = 0; reg_stk_off[r] = 0; }
            if (is_chained_prop) {
                has_int[0] = saved_has_int;
                r_int[0] = saved_r_int;
                has_v[0] = saved_has_v;
                r_v[0] = saved_r_v;
                r_page[0] = saved_r_page;
            }
            continue;
        }

        // MOV Xd, Xm / MOV Wd, Wm (ORR Xd, XZR, Xm / ORR Wd, WZR, Wm)
        if ((cur & 0x7FE003E0) == 0x2A0003E0) {
            uint32_t rm = (cur >> 16) & 0x1F;
            if (rm == 31) {
                has_int[rd] = 1; r_int[rd] = 0; has_v[rd] = 0; r_v_alt[rd] = 0; r_page[rd] = 0;
                reg_stk_base[rd] = 0; reg_stk_off[rd] = 0;
            } else {
                has_v[rd] = has_v[rm]; r_v[rd] = r_v[rm]; r_v_alt[rd] = r_v_alt[rm]; r_page[rd] = r_page[rm];
                has_int[rd] = has_int[rm]; r_int[rd] = r_int[rm];
                reg_stk_base[rd] = reg_stk_base[rm]; reg_stk_off[rd] = reg_stk_off[rm];
            }
            continue;
        }

        // CSEL Xd, Xn, Xm, cond / CSEL Wd, Wn, Wm, cond
        if ((cur & 0x7FE00C00) == 0x1A800000) {
            uint32_t rn = (cur >> 5) & 0x1F, rm = (cur >> 16) & 0x1F;
            if (has_v[rn] && has_v[rm]) {
                uint64_t v_rn = r_v[rn], v_rm = r_v[rm];
                has_v[rd] = 1; r_v[rd] = v_rn; r_v_alt[rd] = v_rm; has_int[rd] = 0;
            } else if (has_v[rn]) {
                has_v[rd] = 1; r_v[rd] = r_v[rn]; r_v_alt[rd] = 0; has_int[rd] = 0;
            } else if (has_v[rm]) {
                has_v[rd] = 1; r_v[rd] = r_v[rm]; r_v_alt[rd] = 0; has_int[rd] = 0;
            } else if (has_int[rn] && has_int[rm]) {
                has_int[rd] = 1; r_int[rd] = r_int[rn]; has_v[rd] = 0;
            } else if (has_int[rn] || has_int[rm]) {
                has_int[rd] = 1; r_int[rd] = has_int[rn] ? r_int[rn] : r_int[rm]; has_v[rd] = 0;
            }
            continue;
        }

        // ADD Xd, SP, #imm12 / ADD Xd, X29, #imm12 / SUB Xd, X29, #imm12
        if ((cur & 0xFF8003E0) == 0x910003E0) {
            uint32_t shift = (cur >> 22) & 1;
            int off = (int)(((cur >> 10) & 0xFFF) << (shift ? 12 : 0));
            reg_stk_base[rd] = 31;
            reg_stk_off[rd] = off;
            has_int[rd] = 0;
            if (slot_stk_base == 31 && off == slot_stk_off) { has_v[rd] = 1; r_v[rd] = slot_v; }
            else { has_v[rd] = 0; }
            continue;
        } else if ((cur & 0xFF8003E0) == 0x910003A0) {
            uint32_t shift = (cur >> 22) & 1;
            int off = (int)(((cur >> 10) & 0xFFF) << (shift ? 12 : 0));
            reg_stk_base[rd] = 29;
            reg_stk_off[rd] = off;
            has_int[rd] = 0;
            if (slot_stk_base == 29 && off == slot_stk_off) { has_v[rd] = 1; r_v[rd] = slot_v; }
            else { has_v[rd] = 0; }
            continue;
        } else if ((cur & 0xFF8003E0) == 0xD10003A0) {
            uint32_t shift = (cur >> 22) & 1;
            int off = -(int)(((cur >> 10) & 0xFFF) << (shift ? 12 : 0));
            reg_stk_base[rd] = 29;
            reg_stk_off[rd] = off;
            has_int[rd] = 0;
            if (slot_stk_base == 29 && off == slot_stk_off) { has_v[rd] = 1; r_v[rd] = slot_v; }
            else { has_v[rd] = 0; }
            continue;
        }

        uint32_t wr1 = 31, wr2 = 31;
        if (instruction_writes_reg(cur, &wr1, &wr2)) {
            if (wr1 < 32) { reg_stk_base[wr1] = 0; reg_stk_off[wr1] = 0; }
            if (wr2 < 32) { reg_stk_base[wr2] = 0; reg_stk_off[wr2] = 0; }
        }

        if ((cur & 0xFFFFFFE0) == 0x2A1F03E0 || (cur & 0xFFFFFFE0) == 0xAA1F03E0) { has_int[rd] = 1; r_int[rd] = 0; has_v[rd] = 0; }
        else if ((cur & 0xFF800000) == 0x52800000 || (cur & 0xFF800000) == 0xD2800000) {
            uint32_t hw = (cur >> 21) & 0x3; uint64_t imm16 = (cur >> 5) & 0xFFFF;
            uint64_t val = imm16 << (hw * 16);
            has_int[rd] = 1;
            r_int[rd] = ((cur & 0x80000000) == 0) ? (int64_t)(int32_t)(uint32_t)val : (int64_t)val;
            has_v[rd] = 0;
        } else if ((cur & 0xFF800000) == 0x12800000 || (cur & 0xFF800000) == 0x92800000) {
            uint32_t hw = (cur >> 21) & 0x3; uint64_t imm16 = (cur >> 5) & 0xFFFF; has_int[rd] = 1; has_v[rd] = 0;
            r_int[rd] = (cur & 0x80000000) ? (int64_t)(~(imm16 << (hw * 16))) : (int)(~(uint32_t)(((uint32_t)imm16) << (hw * 16)));
        } else if (((cur & 0xFF800000) == 0x72800000 || (cur & 0xFF800000) == 0xF2800000) && has_int[rd]) {
            uint32_t hw = (cur >> 21) & 0x3; uint64_t imm16 = (cur >> 5) & 0xFFFF, mask = ~(((uint64_t)0xFFFF) << (hw * 16));
            uint64_t val = (((uint64_t)r_int[rd]) & mask) | (imm16 << (hw * 16));
            r_int[rd] = ((cur & 0x80000000) == 0) ? (int64_t)(int32_t)(uint32_t)val : (int64_t)val;
        } else if (((cur & 0xFF800000) != 0x91000000 && (cur & 0x1F000000) == 0x11000000) || (cur & 0x3F000000) == 0x38000000 || (cur & 0x3F000000) == 0x39000000) {
            has_int[rd] = 0;
        } else if ((cur & 0x9F000000) == 0x10000000) { // ADR Rd, #imm21
            int64_t m = (int64_t)((((cur >> 5) & 0x7FFFF) << 2) | ((cur >> 29) & 0x3)); if (m & 0x100000) m -= 0x200000;
            r_v[rd] = (seg_v + k * 4) + m; has_v[rd] = 1; r_v_alt[rd] = 0; has_int[rd] = 0;
        } else if ((cur & 0x9F000000) == 0x90000000) {
            if (k >= i || rd >= 19) {
                int64_t m = (int64_t)((((cur >> 5) & 0x7FFFF) << 2) | ((cur >> 29) & 0x3)); if (m & 0x100000) m -= 0x200000;
                r_page[rd] = ((seg_v + k * 4) & ~0xFFFULL) + (m << 12); has_v[rd] = 0;
            }
        } else if ((cur & 0xFF800000) == 0x91000000 && r_page[(cur >> 5) & 0x1F]) {
            r_v[rd] = r_page[(cur >> 5) & 0x1F] + ((cur >> 10) & 0xFFF); has_v[rd] = 1; r_v_alt[rd] = 0; has_int[rd] = 0;
        }
    }
    // Если был промежуточный BL (конструктор std::string в X0), то при вызове Get*Property ключ в X0, а дефолт в W1/X1
    int first_r = (preg == 1 && !had_mid_bl) ? 2 : 1;
    int regs[2] = { first_r, (first_r == 1) ? 2 : 1 };

    int check_int = (api_type == API_TYPE_BOOL || api_type == API_TYPE_INT);
    if (check_int) {
        for (int idx = 0; idx < 2; idx++) {
            int r = regs[idx];
            if (has_int[r]) {
                // Игнорируем технические границы min/max в GetIntProperty и таймауты
                if (r_int[r] == -2147483648LL || r_int[r] == 2147483648LL ||
                    r_int[r] == 2147483647LL  || r_int[r] == 9223372036854775807LL ||
                    r_int[r] == (-9223372036854775807LL - 1LL)) continue;
                if (api_type == API_TYPE_STR && r_int[r] == 0) continue;
                if (api_type != API_TYPE_INT && r_int[r] == 0) {
                    strcpy(q->res, "DEFAULT_FALSE");
                } else if (api_type != API_TYPE_INT && r_int[r] == 1) {
                    strcpy(q->res, "DEFAULT_TRUE");
                } else {
                    snprintf(q->res, sizeof(q->res), "DEFAULT_INT: %lld", (long long)r_int[r]);
                }
                return;
            }
        }
    }
    for (int idx = 0; idx < 2; idx++) {
        int r = regs[idx];
        if (has_v[r] && r_v[r] != q->vaddr) {
            const char *s = (const char *)resolve_vaddr_bounded(ctx, r_v[r], 1);
            const char *salt = (r_v_alt[r] && r_v_alt[r] != q->vaddr) ? (const char *)resolve_vaddr_bounded(ctx, r_v_alt[r], 1) : NULL;
            if (is_valid_prop_str(ctx, s, 64)) {
                if (salt && is_valid_prop_str(ctx, salt, 64) && strcmp(s, salt) != 0) {
                    snprintf(q->res, sizeof(q->res), "DEFAULT_STR: \"%s|%s\"", s, salt);
                    return;
                }
                if (api_type == API_TYPE_STR) {
                    snprintf(q->res, sizeof(q->res), "DEFAULT_STR: \"%s\"", s);
                    return;
                } else if (api_type == API_TYPE_BOOL) {
                    if (!strcmp(s, "1") || !strcasecmp(s, "true")) { strcpy(q->res, "DEFAULT_TRUE"); return; }
                    if (!strcmp(s, "0") || !strcasecmp(s, "false")) { strcpy(q->res, "DEFAULT_FALSE"); return; }
                    snprintf(q->res, sizeof(q->res), "DEFAULT_STR: \"%s\"", s);
                    return;
                } else if (api_type == API_TYPE_INT) {
                    char *endp = NULL;
                    long long iv = strtoll(s, &endp, 0);
                    if (endp && *endp == '\0') {
                        snprintf(q->res, sizeof(q->res), "DEFAULT_INT: %lld", iv);
                        return;
                    }
                    snprintf(q->res, sizeof(q->res), "DEFAULT_STR: \"%s\"", s);
                    return;
                }
            }
        }
    }

    // Check stack-allocated SSO std::string (e.g. android::base::GetProperty(key, ""))
    if ((!q->res[0] || !strcmp(q->res, "NOT_A_PROPERTY")) && (api_type == API_TYPE_STR || api_type == API_TYPE_GENERIC)) {
        int def_reg = first_r;
        if (reg_stk_base[def_reg] != 0) {
            int tb = reg_stk_base[def_reg];
            int to = reg_stk_off[def_reg];
            int last_store_type = 0;
            char last_store_char = '\0';
            for (size_t s = scan_start; s < bl_idx; s++) {
                uint32_t m = insts[s];
                // STRH WZR
                if (tb == 31 && (m & 0xFFC003FF) == 0x790003FF) {
                    int off = (int)(((m >> 10) & 0xFFF) << 1);
                    if (off == to) last_store_type = 1;
                } else if (tb == 29 && (m & 0xFFE003FF) == 0x780003BF) {
                    int simm = (int)((m >> 12) & 0x1FF);
                    if (simm & 0x100) simm -= 0x200;
                    if (simm == to) last_store_type = 1;
                }
                // STR WZR
                else if (tb == 31 && (m & 0xFFC003FF) == 0xB90003FF) {
                    int off = (int)(((m >> 10) & 0xFFF) << 2);
                    if (off == to) last_store_type = 1;
                } else if (tb == 29 && (m & 0xFFE003FF) == 0xB80003BF) {
                    int simm = (int)((m >> 12) & 0x1FF);
                    if (simm & 0x100) simm -= 0x200;
                    if (simm == to) last_store_type = 1;
                }
                // STR XZR
                else if (tb == 31 && (m & 0xFFC003FF) == 0xF90003FF) {
                    int off = (int)(((m >> 10) & 0xFFF) << 3);
                    if (off == to) last_store_type = 1;
                } else if (tb == 29 && (m & 0xFFE003FF) == 0xF80003BF) {
                    int simm = (int)((m >> 12) & 0x1FF);
                    if (simm & 0x100) simm -= 0x200;
                    if (simm == to) last_store_type = 1;
                }
                // STP XZR, XZR
                else if (tb == 31 && (m & 0xFFC003FF) == 0xA90003FF) {
                    int simm7 = (int)((m >> 15) & 0x7F);
                    if (simm7 & 0x40) simm7 -= 0x80;
                    int off = simm7 << 3;
                    if (to >= off && to < off + 16) last_store_type = 1;
                } else if (tb == 29 && (m & 0xFFC003FF) == 0xA90003BF) {
                    int simm7 = (int)((m >> 15) & 0x7F);
                    if (simm7 & 0x40) simm7 -= 0x80;
                    int off = simm7 << 3;
                    if (to >= off && to < off + 16) last_store_type = 1;
                }
                // Direct store through def_reg: STRH/STR/STR XZR, [def_reg, #0]
                else if ((m & 0xFFC003FF) == (0x7900003F | (def_reg << 5)) ||
                         (m & 0xFFC003FF) == (0xB900003F | (def_reg << 5)) ||
                         (m & 0xFFC003FF) == (0xF900003F | (def_reg << 5))) {
                    last_store_type = 1;
                }
                // STRH Wt with SSO literal (e.g. 0x3002 for '0')
                else if ((tb == 31 && (m & 0xFFC00000) == 0x79000000 && ((m >> 5) & 0x1F) == 31) ||
                         (tb == 29 && (m & 0xFFE00000) == 0x78000000 && ((m >> 5) & 0x1F) == 29)) {
                    int off = 0;
                    if (tb == 31) off = (int)(((m >> 10) & 0xFFF) << 1);
                    else {
                        int simm = (int)((m >> 12) & 0x1FF);
                        if (simm & 0x100) simm -= 0x200;
                        off = simm;
                    }
                    if (off == to) {
                        uint32_t rt = m & 0x1F;
                        uint64_t v = 0; int got_v = 0;
                        if (has_int[rt]) { v = (uint64_t)r_int[rt]; got_v = 1; }
                        else {
                            for (size_t b = 1; b <= 6 && s >= b; b++) {
                                uint32_t prev = insts[s - b];
                                if ((prev & 0xFF80001F) == (0x52800000 | rt) || (prev & 0xFF80001F) == (0xD2800000 | rt)) {
                                    uint32_t hw = (prev >> 21) & 0x3;
                                    uint64_t imm16 = (prev >> 5) & 0xFFFF;
                                    v = imm16 << (hw * 16);
                                    got_v = 1;
                                    break;
                                }
                            }
                        }
                        if (got_v) {
                            uint8_t b0 = v & 0xFF, b1 = (v >> 8) & 0xFF;
                            if ((b0 & 1) == 0) {
                                int s_len = b0 >> 1;
                                if (s_len == 1 && isprint(b1)) {
                                    last_store_type = 2;
                                    last_store_char = (char)b1;
                                } else if (s_len == 0) {
                                    last_store_type = 1;
                                }
                            }
                        }
                    }
                }
                // STRB Wt with single char / digit or STRB WZR (e.g. mov w8, #0x30; strb w8, [sp])
                else if ((tb == 31 && (m & 0xFFC00000) == 0x39000000 && ((m >> 5) & 0x1F) == 31) ||
                         (tb == 29 && (m & 0xFFE00000) == 0x38000000 && ((m >> 5) & 0x1F) == 29)) {
                    int off = 0;
                    if (tb == 31) off = (int)((m >> 10) & 0xFFF);
                    else {
                        int simm = (int)((m >> 12) & 0x1FF);
                        if (simm & 0x100) simm -= 0x200;
                        off = simm;
                    }
                    if (off == to) {
                        uint32_t rt = m & 0x1F;
                        if (rt == 31) {
                            last_store_type = 1;
                        } else {
                            uint64_t v = 0; int got_v = 0;
                            if (has_int[rt]) { v = (uint64_t)r_int[rt]; got_v = 1; }
                            else {
                                for (size_t b = 1; b <= 6 && s >= b; b++) {
                                    uint32_t prev = insts[s - b];
                                    if ((prev & 0xFF80001F) == (0x52800000 | rt) || (prev & 0xFF80001F) == (0xD2800000 | rt)) {
                                        uint32_t hw = (prev >> 21) & 0x3;
                                        uint64_t imm16 = (prev >> 5) & 0xFFFF;
                                        v = imm16 << (hw * 16);
                                        got_v = 1;
                                        break;
                                    }
                                }
                            }
                            if (got_v) {
                                if (v == 0) last_store_type = 1;
                                else if (v == '0' || v == '1') {
                                    last_store_type = 2;
                                    last_store_char = (char)v;
                                }
                            }
                        }
                    }
                }
            }
            int has_post_int = (api_type == API_TYPE_INT || api_type == API_TYPE_BOOL);
            if (!has_post_int) {
                for (size_t f = 1; f <= 4 && (bl_idx + f) < cnt; f++) {
                    uint32_t post = insts[bl_idx + f];
                    if ((post & 0xFC000000) == 0x94000000) {
                        int32_t cimm = post & 0x03FFFFFF;
                        if (cimm & 0x02000000) cimm -= 0x04000000;
                        uint64_t ctarget = seg_v + ((bl_idx + f) * 4) + (cimm << 2);
                        const char *cfn = get_vaddr_symbol_name(ctx, ctarget);
                        if (cfn && (strstr(cfn, "atoi") || strstr(cfn, "strtol") || strstr(cfn, "strtoll"))) {
                            has_post_int = 1;
                            break;
                        }
                    }
                }
            }
            if (last_store_type == 1) {
                if (has_post_int) strcpy(q->res, (api_type == API_TYPE_INT) ? "DEFAULT_INT: 0" : "DEFAULT_FALSE");
                else strcpy(q->res, "DEFAULT_STR: \"\"");
                return;
            } else if (last_store_type == 2) {
                if (has_post_int) {
                    if (last_store_char == '0') strcpy(q->res, "DEFAULT_FALSE");
                    else if (last_store_char == '1') strcpy(q->res, "DEFAULT_TRUE");
                    else if (isdigit(last_store_char)) snprintf(q->res, sizeof(q->res), "DEFAULT_INT: %d", last_store_char - '0');
                    else snprintf(q->res, sizeof(q->res), "DEFAULT_STR: \"%c\"", last_store_char);
                } else {
                    snprintf(q->res, sizeof(q->res), "DEFAULT_STR: \"%c\"", last_store_char);
                }
                return;
            }
        }
    }

    // Frontier 3: 3-argument property_get(X0, X1, X2) callee-saved default tracking
    if ((!q->res[0] || !strcmp(q->res, "NOT_A_PROPERTY") || !strcmp(q->res, "DYNAMIC_DEFAULT")) && is_prop_get_3arg) {
        int x2_src_reg = -1;
        for (size_t b = 1; b <= 16 && bl_idx >= b; b++) {
            uint32_t bi = insts[bl_idx - b];
            if ((bi & 0x7FE003FF) == 0x2A0003E2) {
                uint32_t rn = (bi >> 16) & 0x1F;
                if (rn >= 19 && rn <= 28) {
                    x2_src_reg = (int)rn;
                    break;
                }
            }
        }
        if (x2_src_reg >= 19 && x2_src_reg <= 28) {
            uint64_t xn_page = 0, xn_vaddr = 0;
            size_t max_b = (i > 4096) ? 4096 : i;
            for (size_t b = 1; b <= max_b; b++) {
                uint32_t bi = insts[i - b];
                if ((bi & 0xFFFFFC1F) == 0xD65F0000 || bi == 0xD69F03E0 ||
                    bi == 0xD50323BF || bi == 0xD50323FF) {
                    break;
                }
                if ((bi & 0x9F000000) == 0x90000000 && (bi & 0x1F) == (uint32_t)x2_src_reg) {
                    int64_t m = (int64_t)((((bi >> 5) & 0x7FFFF) << 2) | ((bi >> 29) & 0x3));
                    if (m & 0x100000) m -= 0x200000;
                    xn_page = (((seg_v + (i - b) * 4) & ~0xFFFULL) + (m << 12));
                    for (size_t fwd = 1; fwd <= 8 && (i - b + fwd) < cnt; fwd++) {
                        uint32_t fi = insts[i - b + fwd];
                        if ((fi & 0xFF800000) == 0x91000000 && (fi & 0x1F) == (uint32_t)x2_src_reg && ((fi >> 5) & 0x1F) == (uint32_t)x2_src_reg) {
                            xn_vaddr = xn_page + ((fi >> 10) & 0xFFF);
                            break;
                        }
                        uint32_t w1 = 31, w2 = 31;
                        if (instruction_writes_reg(fi, &w1, &w2) && (w1 == (uint32_t)x2_src_reg || w2 == (uint32_t)x2_src_reg)) break;
                    }
                    if (xn_vaddr) break;
                }
                else if ((bi & 0x9F000000) == 0x10000000 && (bi & 0x1F) == (uint32_t)x2_src_reg) {
                    int64_t m = (int64_t)((((bi >> 5) & 0x7FFFF) << 2) | ((bi >> 29) & 0x3));
                    if (m & 0x100000) m -= 0x200000;
                    xn_vaddr = (seg_v + (i - b) * 4) + m;
                    break;
                }
            }
            if (xn_vaddr && xn_vaddr != q->vaddr) {
                const char *s = (const char *)resolve_vaddr_bounded(ctx, xn_vaddr, 1);
                if (is_valid_prop_str(ctx, s, 64)) {
                    snprintf(q->res, sizeof(q->res), "DEFAULT_STR: \"%s\"", s);
                    q->status = 2;
                    return;
                }
            }
        }
    }

    // Fallback branch analysis for 2-argument property getters (__system_property_get)
    if (!q->res[0] || !strcmp(q->res, "NOT_A_PROPERTY") || !strcmp(q->res, "DYNAMIC_DEFAULT")) {
        // 1. Branchless CSEL fallback check
        int64_t post_r_int[32] = {0}; int post_has_int[32] = {0}, post_has_v[32] = {0}, post_has_page[32] = {0};
        uint64_t post_r_page[32] = {0}, post_r_v[32] = {0}, post_r_v_alt[32] = {0};
        for (size_t f = 1; f <= 16 && (bl_idx + f) < cnt; f++) {
            uint32_t post = insts[bl_idx + f], prd = post & 0x1F;
            if ((post & 0xFFFFFC1F) == 0xD65F0000) break; // RET
            if ((post & 0x9F000000) == 0x10000000) { // ADR
                int64_t m = (int64_t)((((post >> 5) & 0x7FFFF) << 2) | ((post >> 29) & 0x3));
                if (m & 0x100000) m -= 0x200000;
                post_r_v[prd] = (seg_v + (bl_idx + f) * 4) + m;
                post_has_v[prd] = 1; post_has_int[prd] = 0; post_r_v_alt[prd] = 0; post_has_page[prd] = 0;
            } else if ((post & 0x9F000000) == 0x90000000) { // ADRP
                int64_t m = (int64_t)((((post >> 5) & 0x7FFFF) << 2) | ((post >> 29) & 0x3));
                if (m & 0x100000) m -= 0x200000;
                post_r_page[prd] = ((seg_v + (bl_idx + f) * 4) & ~0xFFFULL) + (m << 12);
                post_has_page[prd] = 1; post_has_v[prd] = 0;
            } else if ((post & 0xFF800000) == 0x91000000 && post_has_page[(post >> 5) & 0x1F]) { // ADD
                post_r_v[prd] = post_r_page[(post >> 5) & 0x1F] + ((post >> 10) & 0xFFF);
                post_has_v[prd] = 1; post_has_int[prd] = 0; post_r_v_alt[prd] = 0; post_has_page[prd] = 0;
            } else if ((post & 0x7FE003E0) == 0x2A0003E0) { // MOV
                uint32_t prm = (post >> 16) & 0x1F;
                if (prm == 31) { post_has_int[prd] = 1; post_r_int[prd] = 0; post_has_v[prd] = 0; post_has_page[prd] = 0; }
                else {
                    post_has_v[prd] = post_has_v[prm]; post_r_v[prd] = post_r_v[prm];
                    post_r_v_alt[prd] = post_r_v_alt[prm]; post_r_page[prd] = post_r_page[prm];
                    post_has_page[prd] = post_has_page[prm];
                    post_has_int[prd] = post_has_int[prm]; post_r_int[prd] = post_r_int[prm];
                }
            } else if ((post & 0x7FE00C00) == 0x1A800000) { // CSEL
                uint32_t prn = (post >> 5) & 0x1F, prm = (post >> 16) & 0x1F;
                uint32_t pcond = (post >> 12) & 0xF;
                // If selecting between two strings (e.g. ternary cond ? "skiavk" : "skiagl"):
                if (post_has_v[prn] && post_has_v[prm]) {
                    uint64_t v_prn = post_r_v[prn], v_prm = post_r_v[prm];
                    post_has_v[prd] = 1; post_r_v[prd] = v_prn; post_r_v_alt[prd] = v_prm;
                    continue;
                }
                // If selecting between buffer and fallback string (after CMP W0, #0):
                if (pcond == 0xC || pcond == 0xD || pcond == 0x1 || pcond == 0x0) {
                    uint32_t f_reg = (pcond == 0xC || pcond == 0x1) ? prm : prn;
                    if (post_has_v[f_reg] && post_r_v[f_reg] != q->vaddr) {
                        const char *s = (const char *)resolve_vaddr_bounded(ctx, post_r_v[f_reg], 1);
                        const char *salt = (post_r_v_alt[f_reg] && post_r_v_alt[f_reg] != q->vaddr) ?
                                           (const char *)resolve_vaddr_bounded(ctx, post_r_v_alt[f_reg], 1) : NULL;
                        if (is_valid_prop_str(ctx, s, 64)) {
                            if (salt && is_valid_prop_str(ctx, salt, 64) && strcmp(s, salt) != 0) {
                                snprintf(q->res, sizeof(q->res), "DEFAULT_STR: \"%s|%s\"", s, salt);
                                return;
                            }
                            snprintf(q->res, sizeof(q->res), "DEFAULT_STR: \"%s\"", s);
                            return;
                        }
                    }
                }
                if (post_has_v[prn]) {
                    post_has_v[prd] = 1; post_r_v[prd] = post_r_v[prn]; post_r_v_alt[prd] = 0;
                } else if (post_has_v[prm]) {
                    post_has_v[prd] = 1; post_r_v[prd] = post_r_v[prm]; post_r_v_alt[prd] = 0;
                }
            }
        }

        // 2. Smart Branch target fallback check (detect DEFAULT_FALSE/TRUE without bogus DEFAULT_INT)
        for (size_t f = 1; f <= 8 && (bl_idx + f) < cnt; f++) {
            uint32_t post = insts[bl_idx + f];
            if ((post & 0xFFFFFC1F) == 0xD65F0000) break; // RET
            int is_fallback_branch = 0;
            int32_t simm19 = 0;
            // CBZ W0, target
            if ((post & 0xFF00001F) == 0x34000000) {
                simm19 = (post >> 5) & 0x7FFFF;
                is_fallback_branch = 1;
            }
            // B.cond target (where cond is LT 0xB, LE 0xD, LO/CC 0x3, LS 0x9, EQ 0x0)
            else if ((post & 0xFF000000) == 0x54000000) {
                uint32_t cond = post & 0x0F;
                if (cond == 0xB || cond == 0xD || cond == 0x3 || cond == 0x9 || cond == 0x0) {
                    simm19 = (post >> 5) & 0x7FFFF;
                    is_fallback_branch = 1;
                }
            }

            if (is_fallback_branch) {
                if (simm19 & 0x40000) simm19 -= 0x80000;
                size_t tgt_idx = bl_idx + f + simm19;
                if (tgt_idx < cnt && tgt_idx > bl_idx && simm19 > 0 && simm19 <= 64) {
                    int found_tgt = 0;
                    for (size_t t = 0; t < 4 && (tgt_idx + t) < cnt; t++) {
                        uint32_t ti = insts[tgt_idx + t];
                        // MOV Rd, #imm (52800000 / D2800000)
                        if ((ti & 0xFF800000) == 0x52800000 || (ti & 0xFF800000) == 0xD2800000) {
                            uint32_t hw = (ti >> 21) & 0x3;
                            uint64_t imm16 = (ti >> 5) & 0xFFFF;
                            uint64_t v = imm16 << (hw * 16);
                            if (v == 0) {
                                strcpy(q->res, "DEFAULT_FALSE");
                                found_tgt = 1;
                                return;
                            } else if (v == 1 && api_type == API_TYPE_BOOL) {
                                strcpy(q->res, "DEFAULT_TRUE");
                                found_tgt = 1;
                                return;
                            }
                            // Never generate DEFAULT_INT: %llu from branch fallback after __system_property_get!
                        }
                        // MOV Rd, WZR / XZR (2A1F03E0 / AA1F03E0)
                        else if ((ti & 0xFFFFFFE0) == 0x2A1F03E0 || (ti & 0xFFFFFFE0) == 0xAA1F03E0) {
                            strcpy(q->res, "DEFAULT_FALSE");
                            found_tgt = 1;
                            return;
                        }
                        // STRB WZR, [Xn, #imm] (390003FF) or STR WZR, [Xn, #imm] (B90003FF)
                        else if ((ti & 0xFFC003FF) == 0x390003FF || (ti & 0xFFC003FF) == 0xB90003FF) {
                            strcpy(q->res, "DEFAULT_FALSE");
                            found_tgt = 1;
                            return;
                        }
                    }
                    if (!found_tgt) {
                        for (size_t chk = 1; chk <= 4 && (bl_idx + f + chk) < tgt_idx; chk++) {
                            uint32_t ci = insts[bl_idx + f + chk];
                            if ((ci & 0xFC000000) == 0x94000000) {
                                int32_t cimm = ci & 0x03FFFFFF;
                                if (cimm & 0x02000000) cimm -= 0x04000000;
                                uint64_t ctarget = seg_v + ((bl_idx + f + chk) * 4) + (cimm << 2);
                                const char *cfn = get_vaddr_symbol_name(ctx, ctarget);
                                if (cfn && (strstr(cfn, "atoi") || strstr(cfn, "strtol") || strstr(cfn, "strtoll"))) {
                                    strcpy(q->res, "DEFAULT_FALSE");
                                    return;
                                }
                            }
                        }
                    }
                } else if (tgt_idx < cnt && tgt_idx > bl_idx && simm19 > 64 && simm19 <= 80) {
                    for (size_t t = 0; t < 4 && (tgt_idx + t) < cnt; t++) {
                        uint32_t ti = insts[tgt_idx + t];
                        if ((ti & 0xFFFFFFE0) == 0x2A1F03E0 || (ti & 0xFFFFFFE0) == 0xAA1F03E0 ||
                            (ti & 0xFFC003FF) == 0x390003FF || (ti & 0xFFC003FF) == 0xB90003FF) {
                            strcpy(q->res, "DEFAULT_FALSE");
                            return;
                        }
                    }
                }
                break;
            }
        }
    }
    if (!q->res[0] || !strcmp(q->res, "NOT_A_PROPERTY")) {
        strcpy(q->res, "DYNAMIC_DEFAULT");
    }
}
static void execute_queries(ElfContext *ctx, PropQuery *queries, int num_props, uint64_t page_bloom, int active) {
    if (active <= 0 || num_props <= 0) return;

    uint64_t page_bits[64] = {0};
    uint64_t min_v = ~0ULL, max_v = 0;
    int htsz = 1;
    while (htsz < num_props * 4) htsz <<= 1;
    int *vht = malloc(htsz * sizeof(int));
    if (!vht) return;
    memset(vht, -1, htsz * sizeof(int));

    for (int m = 0; m < num_props; m++) {
        if (queries[m].status == 1) {
            uint64_t v = queries[m].vaddr;
            if (v < min_v) min_v = v;
            if (v > max_v) max_v = v;
            uint64_t pg = queries[m].page >> 12;
            page_bits[pg & 63] |= (1ULL << ((pg >> 6) & 63));
            uint32_t h = (uint32_t)((v ^ (v >> 12) ^ (v >> 24)) * 2654435761u) & (htsz - 1);
            while (vht[h] != -1) h = (h + 1) & (htsz - 1);
            vht[h] = m;
        }
    }

    for (int p = 0; p < ctx->ehdr->e_phnum; p++) {
        if (ctx->phdr[p].p_type != PT_LOAD || !(ctx->phdr[p].p_flags & PF_X) || ctx->phdr[p].p_offset >= ctx->size) continue;
        size_t fsz = ctx->phdr[p].p_filesz;
        if (ctx->phdr[p].p_offset + fsz > ctx->size) fsz = ctx->size - ctx->phdr[p].p_offset;
        const uint32_t *insts = (const uint32_t *)(ctx->data + ctx->phdr[p].p_offset);
        size_t icnt = fsz / 4; uint64_t seg_v = ctx->phdr[p].p_vaddr;
        for (size_t i = 0; i < icnt; i++) {
            uint32_t i1 = insts[i];
            int is_adr = ((i1 & 0x9F000000) == 0x10000000), is_adrp = ((i1 & 0x9F000000) == 0x90000000);
            if (!is_adr && !is_adrp) continue;
            uint32_t rd = i1 & 0x1F;
            int64_t imm = (int64_t)((((i1 >> 5) & 0x7FFFF) << 2) | ((i1 >> 29) & 0x3));
            if (imm & 0x100000) imm -= 0x200000;
            uint64_t pc = seg_v + i * 4;
            if (is_adrp) {
                uint64_t cpage = (uint64_t)((int64_t)(pc & ~0xFFFULL) + (imm * 4096));
                uint64_t pg = cpage >> 12;
                if (!(page_bits[pg & 63] & (1ULL << ((pg >> 6) & 63)))) continue;
                for (size_t d = 1; d <= 32 && (i + d) < icnt; d++) {
                    uint32_t ca = insts[i + d];
                    if ((ca & 0xFF800000) == 0x91000000 && ((ca >> 5) & 0x1F) == rd) {
                        uint64_t full = cpage + ((ca >> 10) & 0xFFF);
                        if (full < min_v || full > max_v) continue;
                        uint32_t h = (uint32_t)((full ^ (full >> 12) ^ (full >> 24)) * 2654435761u) & (htsz - 1);
                        while (vht[h] != -1) {
                            int m = vht[h];
                            if ((queries[m].status == 1 || (queries[m].status == 2 && !strncmp(queries[m].res, "DYNAMIC_DEFAULT", 15))) && queries[m].vaddr == full) {
                                int was_st = queries[m].status;
                                analyze_call_site(ctx, insts, icnt, seg_v, i, i + d, ca & 0x1F, &queries[m]);
                                if (was_st == 1 && queries[m].status == 2) active--;
                            }
                            h = (h + 1) & (htsz - 1);
                        }
                    }
                }
            } else {
                uint64_t dt = (uint64_t)((int64_t)pc + imm);
                if (dt < min_v || dt > max_v) continue;
                uint64_t pg = dt >> 12;
                if (!(page_bits[pg & 63] & (1ULL << ((pg >> 6) & 63)))) continue;
                uint32_t h = (uint32_t)((dt ^ (dt >> 12) ^ (dt >> 24)) * 2654435761u) & (htsz - 1);
                while (vht[h] != -1) {
                    int m = vht[h];
                    if ((queries[m].status == 1 || (queries[m].status == 2 && !strncmp(queries[m].res, "DYNAMIC_DEFAULT", 15))) && queries[m].vaddr == dt) {
                            int was_st = queries[m].status;
                        analyze_call_site(ctx, insts, icnt, seg_v, i, i, rd, &queries[m]);
                        if (was_st == 1 && queries[m].status == 2) active--;
                    }
                    h = (h + 1) & (htsz - 1);
                }
            }
        }
    }

    if (active > 0 && ctx->has_property_api) {
        uint64_t tbl_bits[64] = {0};
        int tbl_candidates = 0;

        for (int p = 0; p < ctx->ehdr->e_phnum; p++) {
            if (ctx->phdr[p].p_type == PT_LOAD && !(ctx->phdr[p].p_flags & PF_X) && ctx->phdr[p].p_offset < ctx->size) {
                size_t sz = ctx->phdr[p].p_filesz;
                if (ctx->phdr[p].p_offset + sz > ctx->size) sz = ctx->size - ctx->phdr[p].p_offset;
                if (sz < 8) continue;
                const uint64_t *ptrs = (const uint64_t *)(ctx->data + ctx->phdr[p].p_offset);
                for (size_t k = 0; k < (sz - 8) / 8; k++) {
                    uint64_t val = ptrs[k];
                    if (val < min_v || val > max_v) continue;
                    uint64_t vpg = val >> 12;
                    if (!(page_bits[vpg & 63] & (1ULL << ((vpg >> 6) & 63)))) continue;
                    uint32_t h = (uint32_t)((val ^ (val >> 12) ^ (val >> 24)) * 2654435761u) & (htsz - 1);
                    while (vht[h] != -1) {
                        int m = vht[h];
                        if (queries[m].status == 1 && !queries[m].t_vaddr && queries[m].vaddr == val) {
                            uint64_t pv = ctx->phdr[p].p_vaddr + k * 8;
                            if (!is_ptr_in_metadata_symbol(ctx, pv)) {
                                queries[m].t_vaddr = pv;
                                uint64_t pg = pv >> 12, pgm = pg - 1;
                                tbl_bits[pg & 63] |= (1ULL << ((pg >> 6) & 63));
                                tbl_bits[pgm & 63] |= (1ULL << ((pgm >> 6) & 63));
                                tbl_candidates++;
                            }
                        }
                        h = (h + 1) & (htsz - 1);
                    }
                }
            }
        }
        if (ctx->relas_dyn) {
            for (size_t r = 0; r < ctx->count_dyn; r++) {
                if (!is_valid_range(ctx->data, ctx->size, &ctx->relas_dyn[r], sizeof(Elf64_Rela))) break;
                uint64_t val = (uint64_t)ctx->relas_dyn[r].r_addend;
                if (val < min_v || val > max_v) continue;
                uint64_t vpg = val >> 12;
                if (!(page_bits[vpg & 63] & (1ULL << ((vpg >> 6) & 63)))) continue;
                uint32_t h = (uint32_t)((val ^ (val >> 12) ^ (val >> 24)) * 2654435761u) & (htsz - 1);
                while (vht[h] != -1) {
                    int m = vht[h];
                    if (queries[m].status == 1 && !queries[m].t_vaddr && queries[m].vaddr == val) {
                        uint64_t pv = ctx->relas_dyn[r].r_offset;
                        if (!is_ptr_in_metadata_symbol(ctx, pv)) {
                            queries[m].t_vaddr = pv;
                            uint64_t pg = pv >> 12, pgm = pg - 1;
                            tbl_bits[pg & 63] |= (1ULL << ((pg >> 6) & 63));
                            tbl_bits[pgm & 63] |= (1ULL << ((pgm >> 6) & 63));
                            tbl_candidates++;
                        }
                    }
                    h = (h + 1) & (htsz - 1);
                }
            }
        }
        for (int m = 0; m < num_props; m++) {
            if (queries[m].status == 1) {
                if (queries[m].t_vaddr != 0) {
                    uint64_t pv = queries[m].t_vaddr;
                    uint64_t pg = pv >> 12;
                    tbl_bits[pg & 63] |= (1ULL << ((pg >> 6) & 63));
                    tbl_candidates++;
                }
                if (queries[m].g_vaddr != 0) {
                    uint64_t pv = queries[m].g_vaddr;
                    uint64_t pg = pv >> 12;
                    tbl_bits[pg & 63] |= (1ULL << ((pg >> 6) & 63));
                    tbl_candidates++;
                }
            }
        }

        for (int p = 0; p < ctx->ehdr->e_phnum && tbl_candidates > 0; p++) {
            if (ctx->phdr[p].p_type != PT_LOAD || !(ctx->phdr[p].p_flags & PF_X) || ctx->phdr[p].p_offset >= ctx->size) continue;
            size_t fsz = ctx->phdr[p].p_filesz;
            if (ctx->phdr[p].p_offset + fsz > ctx->size) fsz = ctx->size - ctx->phdr[p].p_offset;
            const uint32_t *insts = (const uint32_t *)(ctx->data + ctx->phdr[p].p_offset);
            size_t icnt = fsz / 4; uint64_t seg_v = ctx->phdr[p].p_vaddr;

            for (size_t i = 0; i < icnt && tbl_candidates > 0; i++) {
                uint32_t i1 = insts[i];
                int is_i_adr = ((i1 & 0x9F000000) == 0x10000000);
                int is_i_adrp = ((i1 & 0x9F000000) == 0x90000000);
                if (!is_i_adr && !is_i_adrp) continue;
                uint32_t rd = i1 & 0x1F;
                int64_t imm = (int64_t)((((i1 >> 5) & 0x7FFFF) << 2) | ((i1 >> 29) & 0x3));
                if (imm & 0x100000) imm -= 0x200000;

                uint64_t accessed_base = 0;
                int is_single_ptr = 0;
                size_t d_start = 0;

                if (is_i_adr) {
                    accessed_base = (uint64_t)((int64_t)(seg_v + i * 4) + imm);
                    is_single_ptr = 1;
                    d_start = 0;
                } else {
                    uint64_t cpage = (uint64_t)((int64_t)((seg_v + i * 4) & ~0xFFFULL) + (imm * 4096));
                    uint64_t cpg = cpage >> 12;
                    if (!(tbl_bits[cpg & 63] & (1ULL << ((cpg >> 6) & 63)))) continue;

                    // Находим точный базовый адрес массива или указателя, загружаемого через rd
                    for (size_t d = 1; d <= 8 && (i + d) < icnt; d++) {
                        uint32_t ca = insts[i + d];
                        if (((ca >> 5) & 0x1F) == rd) {
                            if ((ca & 0xFF800000) == 0x91000000) { // ADD Xn, rd, #imm12 (база таблицы)
                                accessed_base = cpage + ((ca >> 10) & 0xFFF);
                                is_single_ptr = 0; d_start = d;
                                break;
                            } else if ((ca & 0xFFC00000) == 0xF9400000) { // LDR Xn, [rd, #uimm12] (указатель)
                                accessed_base = cpage + (((ca >> 10) & 0xFFF) << 3);
                                is_single_ptr = 1; d_start = d;
                                break;
                            }
                        }
                    }
                }
                if (!accessed_base) continue;

                int has_prop_call = -1; int prop_api_type = 0; size_t call_idx = 0;
                uint64_t base_min = (accessed_base >= 64) ? (accessed_base - 64) : 0;
                for (int m = 0; m < num_props; m++) {
                    if (queries[m].status == 1) {
                        if (queries[m].g_vaddr != 0) {
                            if (queries[m].g_vaddr != accessed_base) continue;
                            analyze_call_site(ctx, insts, icnt, seg_v, i, i + d_start, rd, &queries[m]);
                            if (queries[m].status == 2) tbl_candidates--;
                            continue;
                        }
                        if (queries[m].t_vaddr == 0) continue;
                        if (is_single_ptr) {
                            if (queries[m].t_vaddr != accessed_base) continue;
                        } else {
                            if (queries[m].t_vaddr < base_min || queries[m].t_vaddr >= accessed_base + 1024 ||
                                ((queries[m].t_vaddr - accessed_base) % 8 != 0)) continue;
                        }
                        analyze_call_site(ctx, insts, icnt, seg_v, i, i + d_start, rd, &queries[m]);
                        if (queries[m].status == 1) {
                            if (has_prop_call == -1) {
                                has_prop_call = 0;
                                for (size_t k = 1; k <= 128 && (i + k) < icnt; k++) {
                                    uint32_t cand = insts[i + k];
                                    if ((cand & 0xFFFFFC1F) == 0xD65F0000) break;
                                    if ((cand & 0xFC000000) == 0x94000000 || (cand & 0xFC000000) == 0x14000000) {
                                        int32_t s26 = cand & 0x03FFFFFF; if (s26 & 0x02000000) s26 -= 0x04000000;
                                        uint64_t cv = seg_v + ((i + k) * 4) + (s26 << 2);
                                        if ((cand & 0xFC000000) == 0x14000000 && !extract_plt_got_target(ctx, cv)) continue;
                                        int atype = 0;
                                        if (is_call_to_property_api(ctx, cv, 0, &atype, NULL)) {
                                            has_prop_call = 1;
                                            call_idx = i + k;
                                            prop_api_type = atype;
                                            break;
                                        }
                                    }
                                }
                            }
                            if (has_prop_call == 1) {
                                queries[m].status = 2;
                                strcpy(queries[m].res, "DYNAMIC_DEFAULT");
                                // Frontier 1: Extract default from loop instructions before call_idx
                                if (call_idx > 0) {
                                    for (size_t j = 1; j <= 8 && call_idx >= j; j++) {
                                        uint32_t pi = insts[call_idx - j];
                                        if ((pi & 0xFFFFFC1F) == 0xD65F0000) break; // RET
                                        // 1. Check INT / BOOL default in W1
                                        if (prop_api_type == API_TYPE_INT || prop_api_type == API_TYPE_BOOL) {
                                            // MOV W1, WZR / MOV X1, XZR
                                            if (pi == 0x2A1F03E1 || pi == 0xAA1F03E1) {
                                                strcpy(queries[m].res, (prop_api_type == API_TYPE_BOOL) ? "DEFAULT_FALSE" : "DEFAULT_INT: 0");
                                                break;
                                            }
                                            // MOVN W1, #imm16
                                            if ((pi & 0xFF80001F) == 0x12800001) {
                                                uint32_t hw = (pi >> 21) & 0x3;
                                                uint32_t imm16 = (pi >> 5) & 0xFFFF;
                                                int32_t v = (int32_t)(~(imm16 << (hw * 16)));
                                                snprintf(queries[m].res, sizeof(queries[m].res), "DEFAULT_INT: %d", v);
                                                break;
                                            }
                                            // MOV W1, #imm16
                                            if ((pi & 0xFF80001F) == 0x52800001) {
                                                uint32_t hw = (pi >> 21) & 0x3;
                                                uint64_t v = (uint64_t)((pi >> 5) & 0xFFFF) << (hw * 16);
                                                if (v == 0) strcpy(queries[m].res, (prop_api_type == API_TYPE_BOOL) ? "DEFAULT_FALSE" : "DEFAULT_INT: 0");
                                                else if (v == 1 && prop_api_type == API_TYPE_BOOL) strcpy(queries[m].res, "DEFAULT_TRUE");
                                                else snprintf(queries[m].res, sizeof(queries[m].res), "DEFAULT_INT: %llu", (unsigned long long)v);
                                                break;
                                            }
                                        }
                                        // 2. Check STR default in X2 (for property_get(X0, X1, X2))
                                        else if (prop_api_type == API_TYPE_STR) {
                                            if (pi == 0x2A1F03E2 || pi == 0xAA1F03E2) {
                                                strcpy(queries[m].res, "DEFAULT_STR: \"\"");
                                                break;
                                            }
                                        }
                                    }
                                }
                                tbl_candidates--;
                            }
                        } else {
                            tbl_candidates--;
                        }
                    }
                }
            }
        }
    }
    free(vht);
}

static char **g_files = NULL, **g_radar_pats = NULL, **g_file_out = NULL;
static int *g_radar_alive = NULL, *g_radar_strict = NULL, *g_radar_ht = NULL;
static int g_num_files = 0, g_next_file = 0, g_use_regex = 0, g_radar_cnt = 0, g_radar_hsize = 0;
static int g_is_all = 0, g_is_search = 0;
static regex_t g_regex;

static uint32_t fnv1a(const char *s) {
    uint32_t h = 2166136261u;
    while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; }
    return h;
}

static inline uint32_t fnv1a_len(const char *s, size_t len) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) { h ^= (unsigned char)s[i]; h *= 16777619u; }
    return h;
}

static inline int is_valid_rust_str_slice(const uint8_t *s, size_t len) {
    if (len < 3 || len > 120) return 0;
    uint8_t c0 = s[0];
    if (!((c0 >= 'a' && c0 <= 'z') || c0 == '%')) return 0;
    for (size_t k = 1; k < len; k++) {
        uint8_t ch = s[k];
        if (!(isalnum(ch) || ch == '.' || ch == '_' || ch == '-' || ch == '%' || ch == '{' || ch == '}'))
            return 0;
    }
    return 1;
}

static uint64_t g_seen_ino[16384];

static void *mt_worker(void *arg) {
    int is_radar = (int)(intptr_t)arg;
    while (1) {
        int idx = __sync_fetch_and_add(&g_next_file, 1);
        if (idx >= g_num_files) break;
        const char *path = g_files[idx];
        int fd = open(path, O_RDONLY); if (fd < 0) continue;
        struct stat st;
        if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size < (off_t)sizeof(Elf64_Ehdr)) { close(fd); continue; }
        uint64_t ino_key = ((uint64_t)st.st_dev << 32) ^ (uint64_t)st.st_ino;
        if (ino_key) {
            uint32_t ih = (uint32_t)(ino_key ^ (ino_key >> 17)) & 16383;
            int dup = 0;
            for (int probe = 0; probe < 16384; probe++) {
                uint64_t cur_ino = g_seen_ino[ih];
                if (cur_ino == ino_key) { dup = 1; break; }
                if (cur_ino == 0 && __sync_bool_compare_and_swap(&g_seen_ino[ih], 0, ino_key)) break;
                if (g_seen_ino[ih] == ino_key) { dup = 1; break; }
                ih = (ih + 1) & 16383;
            }
            if (dup) { close(fd); continue; }
        }
        size_t size = (size_t)st.st_size;
        const uint8_t *data = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
        close(fd);
        if (data == MAP_FAILED) continue;
        Elf64_Ehdr *ehdr = (Elf64_Ehdr *)data;
        if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) || ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
            !is_valid_range(data, size, data + ehdr->e_phoff, (size_t)ehdr->e_phnum * sizeof(Elf64_Phdr))) {
            // В режиме Радара фоллбэк разрешён только для 32-битных ELF (\x7fELF), исключая .apk/.jar/.dex/.vdex/.pb
            if (is_radar && !memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) {
                size_t i = 0;
                while (i < size) {
                    if (!isprint(data[i])) { i++; continue; }
                    size_t start = i;
                    while (i < size && isprint(data[i])) i++;
                    size_t l = i - start;
                    if (i < size && data[i] == '\0' && l >= 4 && l <= 120) {
                        const char *s = (const char *)(data + start);
                        uint32_t h = fnv1a(s) & (g_radar_hsize - 1);
                        while (g_radar_ht[h] != -1) {
                            int pidx = g_radar_ht[h];
                            if (!g_radar_strict[pidx] && !strcmp(g_radar_pats[pidx], s)) {
                                __sync_lock_test_and_set(&g_radar_alive[pidx], 1);
                                break;
                            }
                            h = (h + 1) & (g_radar_hsize - 1);
                        }
                    }
                    i++;
                }
            }
            munmap((void*)data, size); continue;
        }
        Elf64_Phdr *phdr = (Elf64_Phdr *)(data + ehdr->e_phoff);
        ElfContext ctx;
        init_elf_context(&ctx, data, size, ehdr, phdr);
        if (!is_radar && !ctx.has_property_api && !ctx.dlsym_got && !ctx.guard_got_cnt && ctx.sym_count > 0) {
            munmap((void*)data, size); continue;
        }
        int has_ro_seg = 0;
        for (int p = 0; p < ehdr->e_phnum; p++) {
            if (phdr[p].p_type == PT_LOAD && !(phdr[p].p_flags & PF_X) && !(phdr[p].p_flags & PF_W)) {
                has_ro_seg = 1; break;
            }
        }
        size_t qcap = 256; int qcnt = 0, active = 0; uint64_t bloom = 0;
        PropQuery *qs = calloc(qcap, sizeof(PropQuery));
        for (int p = 0; p < ehdr->e_phnum && qs; p++) {
            if (phdr[p].p_type != PT_LOAD || (has_ro_seg && (phdr[p].p_flags & PF_X)) || phdr[p].p_offset >= size) continue;
            size_t slen = phdr[p].p_filesz; if (phdr[p].p_offset + slen > size) slen = size - phdr[p].p_offset;
            const uint8_t *seg = data + phdr[p].p_offset;
            size_t start = 0;
            while (start < slen) {
                uint8_t c0 = seg[start];
                if (c0 == '\0') { start++; continue; }
                const uint8_t *nul = memchr(seg + start, '\0', slen - start);
                if (!nul) break;
                size_t l = (size_t)(nul - (seg + start));
                int clean_str = (l >= 3 && l <= 120 && ((c0 >= 'a' && c0 <= 'z') || (is_radar && c0 == '%')));
                if (clean_str) {
                    for (size_t k = 1; k < l; k++) {
                        uint8_t ch = seg[start + k];
                        if (!(isalnum(ch) || ch == '.' || ch == '_' || ch == '-' || (is_radar && (ch == '%' || ch == '{' || ch == '}')))) {
                            clean_str = 0; break;
                        }
                    }
                }
                if (!clean_str) {
                    if (is_radar) {
                        const uint8_t *cur_p = seg + start;
                        while (cur_p < nul) {
                            while (cur_p < nul && !(isalnum(*cur_p) || *cur_p == '.' || *cur_p == '_' || *cur_p == '-' || *cur_p == '%' || *cur_p == '{' || *cur_p == '}')) cur_p++;
                            const uint8_t *tok_s = cur_p;
                            while (cur_p < nul && (isalnum(*cur_p) || *cur_p == '.' || *cur_p == '_' || *cur_p == '-' || *cur_p == '%' || *cur_p == '{' || *cur_p == '}')) cur_p++;
                            if (tok_s < cur_p) {
                                size_t tl = (size_t)(cur_p - tok_s);
                                if (is_valid_rust_str_slice(tok_s, tl)) {
                                    uint32_t h = fnv1a_len((const char *)tok_s, tl) & (g_radar_hsize - 1);
                                    while (g_radar_ht[h] != -1) {
                                        int pidx = g_radar_ht[h];
                                        if (!strncmp(g_radar_pats[pidx], (const char *)tok_s, tl) && g_radar_pats[pidx][tl] == '\0') {
                                            if (!g_radar_strict[pidx] && !is_aidl_or_type_descriptor(g_radar_pats[pidx])) {
                                                __sync_lock_test_and_set(&g_radar_alive[pidx], 1);
                                            } else if (!g_radar_alive[pidx] && !is_aidl_or_type_descriptor(g_radar_pats[pidx])) {
                                                if ((size_t)qcnt >= qcap) { qcap *= 2; qs = realloc(qs, qcap * sizeof(PropQuery)); }
                                                uint64_t v = file_offset_to_vaddr(ehdr, phdr, phdr[p].p_offset + (size_t)(tok_s - seg));
                                                qs[qcnt] = (PropQuery){g_radar_pats[pidx], v, v & ~0xFFFULL, v & 0xFFFULL, 1, pidx, "NOT_A_PROPERTY"};
                                                bloom |= (1ULL << ((qs[qcnt].page >> 12) & 63)); qcnt++; active++;
                                            }
                                            break;
                                        }
                                        h = (h + 1) & (g_radar_hsize - 1);
                                    }
                                }
                            }
                        }
                    }
                    const uint8_t *tp = nul - 1;
                    while (tp >= seg + start && (isalnum(*tp) || *tp == '.' || *tp == '_' || *tp == '-' || (is_radar && (*tp == '%' || *tp == '{' || *tp == '}')))) tp--;
                    tp++;
                    if (tp >= seg + start && tp < nul) {
                        size_t tl = (size_t)(nul - tp);
                        uint8_t tc = *tp;
                        if (tl >= 3 && tl <= 91 && ((tc >= 'a' && tc <= 'z') || (is_radar && tc == '%'))) {
                            start = (size_t)(tp - seg);
                            c0 = tc;
                            l = tl;
                            clean_str = 1;
                        }
                    }
                }
                if (clean_str && l >= 3 && l <= 120 && ((c0 >= 'a' && c0 <= 'z') || (is_radar && c0 == '%'))) {
                    const char *s = (const char *)(seg + start);
                    if (is_radar) {
                        uint32_t h = fnv1a(s) & (g_radar_hsize - 1);
                        while (g_radar_ht[h] != -1) {
                            int pidx = g_radar_ht[h];
                            if (!strcmp(g_radar_pats[pidx], s)) {
                                if (!g_radar_strict[pidx] && !is_aidl_or_type_descriptor(s)) {
                                    __sync_lock_test_and_set(&g_radar_alive[pidx], 1);
                                } else if (!g_radar_alive[pidx] && !is_aidl_or_type_descriptor(s)) {
                                    if ((size_t)qcnt >= qcap) { qcap *= 2; qs = realloc(qs, qcap * sizeof(PropQuery)); }
                                    uint64_t v = file_offset_to_vaddr(ehdr, phdr, phdr[p].p_offset + start);
                                    qs[qcnt] = (PropQuery){s, v, v & ~0xFFFULL, v & 0xFFFULL, 1, pidx, "NOT_A_PROPERTY"};
                                    bloom |= (1ULL << ((qs[qcnt].page >> 12) & 63)); qcnt++; active++;
                                }
                                break;
                            }
                            h = (h + 1) & (g_radar_hsize - 1);
                        }
                    } else if (is_candidate_prop_syntax(s, l) && (!g_use_regex || !regexec(&g_regex, s, 0, NULL, 0))) {
                        if ((size_t)qcnt >= qcap) { qcap *= 2; qs = realloc(qs, qcap * sizeof(PropQuery)); }
                        uint64_t v = file_offset_to_vaddr(ehdr, phdr, phdr[p].p_offset + start);
                        int aidl = is_aidl_or_type_descriptor(s);
                        qs[qcnt] = (PropQuery){s, v, v & ~0xFFFULL, v & 0xFFFULL, aidl ? 2 : 1, -1, "NOT_A_PROPERTY"};
                        if (!aidl) { bloom |= (1ULL << ((qs[qcnt].page >> 12) & 63)); active++; }
                        qcnt++;
                    }
                }
                start = (size_t)(nul - seg) + 1;
            }
        }
        if (active > 0) {
            execute_queries(&ctx, qs, qcnt, bloom, active);
        }
        if (qcnt > 0) {
            if (is_radar) {
                for (int m = 0; m < qcnt; m++) if (qs[m].status == 2) __sync_lock_test_and_set(&g_radar_alive[qs[m].pat_idx], 1);
            } else {
                const char *bn = strrchr(path, '/'); bn = bn ? bn + 1 : path;
                size_t bsz = 0;
                char *buf = NULL;
                FILE *mem = open_memstream(&buf, &bsz);
                if (mem) {
                    for (int m = 0; m < qcnt; m++) {
                        if ((g_is_all || g_is_search) && (qs[m].status != 2 || !strcmp(qs[m].res, "NOT_A_PROPERTY"))) continue;
                        fprintf(mem, "%s|%s|%s\n", qs[m].name, qs[m].res, bn);
                    }
                    fclose(mem);
                    g_file_out[idx] = buf;
                }
            }
        }
        free(qs); munmap((void*)data, size);
    }
    return NULL;
}

// ============================================================================
// Нативный многопоточный декодер байткода Dalvik (.dex внутри .jar / .apk)
// ============================================================================
enum DexPropApi {
    DEX_API_NONE = 0,
    DEX_API_BOOL,
    DEX_API_INT,
    DEX_API_LONG,
    DEX_API_STR1,
    DEX_API_STR2,
    DEX_API_SET,
    DEX_API_PERF,
    DEX_API_DC_BOOL,
    DEX_API_DC_INT,
    DEX_API_DC_LONG,
    DEX_API_DC_STR,
    DEX_API_DC_PROP1
};

typedef struct {
    const uint8_t *zip_data;
    size_t zip_size;
    uint32_t comp_off, comp_sz, uncomp_sz;
    uint16_t method;
    const char *jar_name;
    char *out_buf;
    int *map_ref;
} DexTask;

static DexTask *g_dex_tasks = NULL;
static int g_dex_task_cnt = 0, g_next_dex_task = 0;

static inline uint32_t read_uleb128(const uint8_t **p, const uint8_t *end) {
    const uint8_t *ptr = *p;
    uint32_t res = 0; int shift = 0;
    while (ptr < end) {
        uint8_t b = *ptr++;
        res |= (uint32_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
    }
    *p = ptr;
    return res;
}

static const char *dex_get_str(const uint8_t *dex, size_t dex_sz, const uint32_t *str_ids, uint32_t str_cnt, uint32_t idx, size_t *out_len) {
    if (idx >= str_cnt) return NULL;
    uint32_t off = str_ids[idx];
    if (off >= dex_sz) return NULL;
    const uint8_t *p = dex + off, *end = dex + dex_sz;
    uint32_t u16_len = read_uleb128(&p, end);
    (void)u16_len;
    if (p >= end) return NULL;
    const uint8_t *nul = memchr(p, '\0', (size_t)(end - p));
    if (!nul) return NULL;
    if (out_len) *out_len = (size_t)(nul - p);
    return (const char *)p;
}

static inline int is_dex_token_str(const char *s, size_t len) {
    if (!s || len < 2 || len > 91) return 0;
    if (!isalnum((unsigned char)s[0]) || !isalnum((unsigned char)s[len - 1])) return 0;
    for (size_t i = 0; i < len; i++) {
        char ch = s[i];
        if (!(isalnum((unsigned char)ch) || ch == '.' || ch == '_' || ch == '-' || ch == '/')) return 0;
    }
    return 1;
}

static int is_dex_prop_cand(const char *s, size_t len) {
    if (!is_candidate_prop_syntax(s, len)) return 0;
    return 1;
}

static int32_t dex_find_str_bsearch(const uint8_t *dex, size_t dex_sz, const uint32_t *str_ids, uint32_t str_cnt, const char *target) {
    int32_t low = 0, high = (int32_t)str_cnt - 1;
    while (low <= high) {
        int32_t mid = low + (high - low) / 2;
        const char *s = dex_get_str(dex, dex_sz, str_ids, str_cnt, (uint32_t)mid, NULL);
        if (!s) return -1;
        int cmp = strcmp(target, s);
        if (cmp == 0) return mid;
        if (cmp < 0) high = mid - 1;
        else low = mid + 1;
    }
    return -1;
}

static int dex_has_prefix_bsearch(const uint8_t *dex, size_t dex_sz, const uint32_t *str_ids, uint32_t str_cnt, const char *pref, size_t plen) {
    int32_t low = 0, high = (int32_t)str_cnt - 1;
    while (low <= high) {
        int32_t mid = low + (high - low) / 2;
        const char *s = dex_get_str(dex, dex_sz, str_ids, str_cnt, (uint32_t)mid, NULL);
        if (!s) return 0;
        int cmp = strncmp(pref, s, plen);
        if (cmp == 0) return 1;
        if (cmp < 0) high = mid - 1;
        else low = mid + 1;
    }
    return 0;
}

static uint8_t dex_proto_to_wrap_api(const uint8_t *dex, size_t dex_sz, const uint32_t *str_ids, uint32_t str_cnt,
                                     uint32_t proto_off, uint32_t proto_cnt, uint16_t p_idx, int32_t str_type_idx, int is_dc) {
    if (p_idx >= proto_cnt) return DEX_API_NONE;
    const uint32_t *pr = (const uint32_t *)(dex + proto_off + p_idx * 12);
    uint32_t sh_idx = pr[0], ret_type = pr[1], param_off = pr[2];
    if (!param_off || (uint64_t)param_off + 6 > dex_sz) return DEX_API_NONE;
    uint32_t p_cnt = *(const uint32_t *)(dex + param_off);
    if (p_cnt < 1 || p_cnt > 6 || (uint64_t)param_off + 4 + p_cnt * 2 > dex_sz) return DEX_API_NONE;
    const uint16_t *ptypes = (const uint16_t *)(dex + param_off + 4);
    if (str_type_idx >= 0) {
        int has_s = 0;
        for (uint32_t i = 0; i < p_cnt; i++) {
            if (ptypes[i] == (uint16_t)str_type_idx) { has_s = 1; break; }
        }
        if (!has_s) return DEX_API_NONE;
    }
    const char *sh = dex_get_str(dex, dex_sz, str_ids, str_cnt, sh_idx, NULL);
    if (!sh || !sh[0]) return DEX_API_NONE;
    if (is_dc) {
        if (p_cnt == 1 || (p_cnt == 2 && ptypes[1] != (uint16_t)str_type_idx)) return DEX_API_DC_PROP1;
        if (sh[0] == 'Z') return DEX_API_DC_BOOL;
        if (sh[0] == 'I') return DEX_API_DC_INT;
        if (sh[0] == 'J') return DEX_API_DC_LONG;
        if (sh[0] == 'F' || sh[0] == 'L') return DEX_API_DC_STR;
        return DEX_API_NONE;
    }
    if (sh[0] == 'Z' && (p_cnt >= 1 && p_cnt <= 4)) return DEX_API_BOOL;
    if (sh[0] == 'I' && (p_cnt >= 1 && p_cnt <= 4)) return DEX_API_INT;
    if (sh[0] == 'J' && (p_cnt >= 1 && p_cnt <= 4)) return DEX_API_LONG;
    if (sh[0] == 'F' && (p_cnt >= 1 && p_cnt <= 4)) return DEX_API_STR1;
    if (sh[0] == 'L' && (str_type_idx < 0 || ret_type == (uint32_t)str_type_idx)) {
        if (p_cnt == 1) return DEX_API_STR1;
        if (p_cnt >= 2 && p_cnt <= 4) return DEX_API_STR2;
    }
    if (!strcmp(sh, "VLL")) return DEX_API_SET;
    return DEX_API_NONE;
}

static uint8_t check_multidex_static_getter(const uint8_t *dex, size_t dex_sz, const uint32_t *str_ids, uint32_t str_cnt,
                                            const uint32_t *type_ids, uint32_t type_cnt, uint32_t proto_off, uint32_t proto_cnt,
                                            uint32_t meth_off, uint32_t meth_cnt, uint16_t midx, int32_t str_type_idx, const char *pname) {
    if (midx >= meth_cnt || !pname) return DEX_API_NONE;
    if (strncmp(pname, "persist.", 8) && strncmp(pname, "ro.", 3) &&
        strncmp(pname, "sys.", 4) && strncmp(pname, "debug.", 6) && strncmp(pname, "vendor.", 7)) {
        return DEX_API_NONE;
    }
    const uint16_t *mid = (const uint16_t *)(dex + meth_off + midx * 8);
    uint16_t c_idx = mid[0], p_idx = mid[1];
    uint32_t n_idx = *(const uint32_t *)(mid + 2);
    if (c_idx >= type_cnt || p_idx >= proto_cnt) return DEX_API_NONE;

    const char *cdesc = dex_get_str(dex, dex_sz, str_ids, str_cnt, type_ids[c_idx], NULL);
    const char *mname = dex_get_str(dex, dex_sz, str_ids, str_cnt, n_idx, NULL);
    if (!cdesc || !mname) return DEX_API_NONE;

    if (!strncmp(cdesc, "Ljava/", 6) || !strncmp(cdesc, "Ljavax/", 7) || !strncmp(cdesc, "Lkotlin/", 8) ||
        !strncmp(cdesc, "Ldalvik/", 8) || !strncmp(cdesc, "Lorg/json/", 10) || !strncmp(cdesc, "Landroid/text/", 14) ||
        !strncmp(cdesc, "Landroid/util/", 14) || !strncmp(cdesc, "Landroid/os/Bundle", 18) ||
        !strncmp(cdesc, "Landroid/os/BaseBundle", 22) || !strncmp(cdesc, "Landroid/content/", 17) ||
        !strncmp(cdesc, "Landroid/net/", 13) || !strncmp(cdesc, "Landroid/database/", 18) ||
        strstr(cdesc, "Settings") || strstr(cdesc, "Log") || strstr(cdesc, "Json") || strstr(cdesc, "JSON") ||
        strstr(cdesc, "Prefs") || strstr(cdesc, "Preferences")) {
        return DEX_API_NONE;
    }
    if (!strncmp(mname, "set", 3) || !strncmp(mname, "put", 3) || !strncmp(mname, "write", 5) ||
        !strncmp(mname, "parse", 5) || !strncmp(mname, "valueOf", 7) || !strncmp(mname, "format", 6) ||
        !strncmp(mname, "check", 5) || !strncmp(mname, "enforce", 7) || !strncmp(mname, "remove", 6) ||
        !strncmp(mname, "delete", 6) || !strncmp(mname, "clear", 5) || !strncmp(mname, "log", 3) ||
        !strncmp(mname, "print", 5) || !strncmp(mname, "opt", 3) || !strncmp(mname, "create", 6) ||
        !strncmp(mname, "init", 4) || !strncmp(mname, "notify", 6) || !strncmp(mname, "send", 4) ||
        !strncmp(mname, "post", 4) || !strncmp(mname, "register", 8) || !strncmp(mname, "add", 3) ||
        !strncmp(mname, "append", 6) || !strncmp(mname, "split", 5) || !strncmp(mname, "contains", 8) ||
        !strncmp(mname, "equals", 6)) {
        return DEX_API_NONE;
    }
    uint8_t w_api = dex_proto_to_wrap_api(dex, dex_sz, str_ids, str_cnt, proto_off, proto_cnt, p_idx, str_type_idx, 0);
    if (w_api == DEX_API_SET) return DEX_API_NONE;
    if (w_api == DEX_API_STR2 && strlen(mname) > 3 && strncmp(mname, "get", 3) != 0) return DEX_API_NONE;
    return w_api;
}

static int dalvik_insn_width(const uint16_t *insns, uint32_t pc, uint32_t insns_sz) {
    uint16_t inst = insns[pc];
    uint8_t op = inst & 0xFF;
    if (op == 0x00) {
        if (inst == 0x0100 && pc + 1 < insns_sz) return 4 + insns[pc + 1] * 2;
        if (inst == 0x0200 && pc + 1 < insns_sz) return 2 + insns[pc + 1] * 4;
        if (inst == 0x0300 && pc + 3 < insns_sz) {
            uint32_t elem_w = insns[pc + 1];
            uint32_t elem_c = (uint32_t)insns[pc + 2] | ((uint32_t)insns[pc + 3] << 16);
            return 4 + (int)((elem_w * elem_c + 1) / 2);
        }
        return 1;
    }
    if ((op >= 0x01 && op <= 0x01) || op == 0x04 || op == 0x07 || (op >= 0x0a && op <= 0x12) ||
        (op >= 0x1d && op <= 0x1e) || op == 0x21 || (op >= 0x27 && op <= 0x28) ||
        (op >= 0x3e && op <= 0x43) || op == 0x73 || (op >= 0x79 && op <= 0x8f) ||
        (op >= 0xb0 && op <= 0xcf) || (op >= 0xe3 && op <= 0xf9)) return 1;
    if (op == 0x02 || op == 0x05 || op == 0x08 || op == 0x13 || op == 0x15 || op == 0x16 ||
        op == 0x19 || op == 0x1a || op == 0x1c || (op >= 0x1f && op <= 0x20) ||
        (op >= 0x22 && op <= 0x23) || op == 0x29 || (op >= 0x2d && op <= 0x3d) ||
        (op >= 0x44 && op <= 0x6d) || (op >= 0x90 && op <= 0xaf) ||
        (op >= 0xd0 && op <= 0xe2) || (op >= 0xfe && op <= 0xff)) return 2;
    if (op == 0x18) return 5;
    if (op == 0xfa || op == 0xfb) return 4;
    return 3;
}

static inline int is_lowercase_flag_token(const char *s, size_t len) {
    if (!s || len < 10 || len > 72) return 0;
    if (s[0] < 'a' || s[0] > 'z') return 0;
    char last = s[len - 1];
    if (!((last >= 'a' && last <= 'z') || (last >= '0' && last <= '9'))) return 0;
    int has_sep = 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c == '_' || c == '-' || c == '/') has_sep = 1;
        else if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.')) return 0;
    }
    return has_sep;
}

static void emit_dex_dc_token(FILE *out, const char *s, size_t slen, const char *jar_name) {
    if (!s || slen < 10 || !is_dex_token_str(s, slen)) return;
    if (!strchr(s, '_') && !strchr(s, '-') && !strchr(s, '/')) return;
    fprintf(out, "__DEX_TOKEN__:%s=DYNAMIC_DEFAULT|%s\n", s, jar_name);
    const char *slash = strrchr(s, '/');
    if (slash && strlen(slash + 1) >= 10 && (strchr(slash + 1, '_') || strchr(slash + 1, '-'))) {
        fprintf(out, "__DEX_TOKEN__:%s=DYNAMIC_DEFAULT|%s\n", slash + 1, jar_name);
    }
    const char *dot = strrchr(s, '.');
    if (dot && strlen(dot + 1) >= 10 && (strchr(dot + 1, '_') || strchr(dot + 1, '-'))) {
        fprintf(out, "__DEX_TOKEN__:%s=DYNAMIC_DEFAULT|%s\n", dot + 1, jar_name);
    }
}

static void parse_dex_buffer(const uint8_t *dex, size_t dex_sz, const char *jar_name, FILE *out) {
    if (dex_sz < 112 || memcmp(dex, "dex\n", 4) != 0) return;
    const uint32_t *hdr = (const uint32_t *)dex;
    uint32_t str_cnt = hdr[14], str_off = hdr[15];
    uint32_t type_cnt = hdr[16], type_off = hdr[17];
    uint32_t proto_cnt = hdr[18], proto_off = hdr[19];
    uint32_t field_cnt = hdr[20], field_off = hdr[21];
    uint32_t meth_cnt = hdr[22], meth_off = hdr[23];
    uint32_t cls_cnt = hdr[24], cls_off = hdr[25];

    if ((uint64_t)str_off + str_cnt * 4 > dex_sz || (uint64_t)type_off + type_cnt * 4 > dex_sz ||
        (uint64_t)proto_off + proto_cnt * 12 > dex_sz || (uint64_t)field_off + field_cnt * 8 > dex_sz ||
        (uint64_t)meth_off + meth_cnt * 8 > dex_sz || (uint64_t)cls_off + cls_cnt * 32 > dex_sz ||
        meth_cnt > 65536 || field_cnt > 65536) return;

    const uint32_t *str_ids = (const uint32_t *)(dex + str_off);
    const uint32_t *type_ids = (const uint32_t *)(dex + type_off);

    int has_writable_flags = 0;
    for (uint32_t c = 0; c < cls_cnt; c++) {
        uint32_t c_type_idx = *(const uint32_t *)(dex + cls_off + c * 32);
        const char *cdesc = (c_type_idx < type_cnt) ? dex_get_str(dex, dex_sz, str_ids, str_cnt, type_ids[c_type_idx], NULL) : NULL;
        if (cdesc && strstr(cdesc, "WritableFlags")) { has_writable_flags = 1; break; }
    }
    if (!has_writable_flags) {
        for (uint32_t i = 0; i < str_cnt; i++) {
            size_t slen = 0;
            const char *s = dex_get_str(dex, dex_sz, str_ids, str_cnt, i, &slen);
            if (!s || slen < 6 || slen > 91) continue;
            if (is_dex_prop_cand(s, slen)) {
                fprintf(out, "__DEX_TOKEN__:%s=DYNAMIC_DEFAULT|%s\n", s, jar_name);
            } else if (is_lowercase_flag_token(s, slen)) {
                emit_dex_dc_token(out, s, slen, jar_name);
            }
        }
    }

    int32_t str_perf = dex_find_str_bsearch(dex, dex_sz, str_ids, str_cnt, "perfGetProp");
    int32_t str_sysprop_dot = dex_find_str_bsearch(dex, dex_sz, str_ids, str_cnt, "android.os.SystemProperties");
    int32_t str_jls = dex_find_str_bsearch(dex, dex_sz, str_ids, str_cnt, "Ljava/lang/String;");
    int32_t str_on_prop_chg = dex_find_str_bsearch(dex, dex_sz, str_ids, str_cnt, "onPropertiesChanged");
    int32_t str_type_idx = -1;

    // 1 = *SystemProperties*, 2 = *DeviceConfig; / *DeviceConfigUtils;, 3 = *DeviceConfig$Properties; / *AconfigPackage; / *FeatureFlagUtils; / *OnPropertiesChangedListener;
    uint8_t *is_prop_type = calloc(type_cnt, 1);
    if (!is_prop_type) return;
    int has_any_prop_class = 0;

    for (uint32_t t = 0; t < type_cnt; t++) {
        uint32_t desc_idx = type_ids[t];
        if (str_jls >= 0 && desc_idx == (uint32_t)str_jls) str_type_idx = (int32_t)t;
        const char *desc = dex_get_str(dex, dex_sz, str_ids, str_cnt, desc_idx, NULL);
        if (!desc) continue;
        if (strstr(desc, "SystemProperties")) {
            is_prop_type[t] = 1;
            has_any_prop_class = 1;
        } else if (strstr(desc, "DeviceConfig;") || strstr(desc, "DeviceConfigUtils;")) {
            is_prop_type[t] = 2;
            has_any_prop_class = 1;
        } else if (strstr(desc, "DeviceConfig$Properties;") || strstr(desc, "AconfigPackage;") ||
                   strstr(desc, "FeatureFlagUtils;") || strstr(desc, "OnPropertiesChangedListener;")) {
            is_prop_type[t] = 3;
            has_any_prop_class = 1;
        }
    }

    if (!has_any_prop_class && str_perf < 0 && str_sysprop_dot < 0) {
        free(is_prop_type);
        return;
    }

    uint8_t *meth_api = calloc(meth_cnt, 1);
    if (!meth_api) { free(is_prop_type); return; }
    int has_any_api = 0;

    for (uint32_t m = 0; m < meth_cnt; m++) {
        const uint16_t *mid = (const uint16_t *)(dex + meth_off + m * 8);
        uint16_t c_idx = mid[0], p_idx = mid[1];
        uint32_t n_idx = *(const uint32_t *)(mid + 2);
        if (c_idx >= type_cnt || p_idx >= proto_cnt) continue;

        if (str_perf >= 0 && n_idx == (uint32_t)str_perf) {
            meth_api[m] = DEX_API_PERF; has_any_api = 1; continue;
        }

        uint8_t pt = is_prop_type[c_idx];
        const char *mname = dex_get_str(dex, dex_sz, str_ids, str_cnt, n_idx, NULL);
        if (!mname) continue;

        if (pt == 1) {
            if (!strcmp(mname, "getBoolean")) { meth_api[m] = DEX_API_BOOL; has_any_api = 1; }
            else if (!strcmp(mname, "getInt")) { meth_api[m] = DEX_API_INT; has_any_api = 1; }
            else if (!strcmp(mname, "getLong")) { meth_api[m] = DEX_API_LONG; has_any_api = 1; }
            else if (!strcmp(mname, "set")) { meth_api[m] = DEX_API_SET; has_any_api = 1; }
            else if (!strcmp(mname, "get")) {
                uint32_t sh_idx = *(const uint32_t *)(dex + proto_off + p_idx * 12);
                const char *sh = dex_get_str(dex, dex_sz, str_ids, str_cnt, sh_idx, NULL);
                meth_api[m] = (sh && !strcmp(sh, "LLL")) ? DEX_API_STR2 : DEX_API_STR1;
                has_any_api = 1;
            }
        } else if (pt == 2) {
            if (!strcmp(mname, "getBoolean") || !strncmp(mname, "isFeatureEnabled", 16) ||
                !strncmp(mname, "isTetheringFeature", 18)) {
                meth_api[m] = DEX_API_DC_BOOL; has_any_api = 1;
            }
            else if (!strcmp(mname, "getInt") || !strcmp(mname, "getDeviceConfigPropertyInt")) {
                meth_api[m] = DEX_API_DC_INT; has_any_api = 1;
            }
            else if (!strcmp(mname, "getLong")) { meth_api[m] = DEX_API_DC_LONG; has_any_api = 1; }
            else if (!strcmp(mname, "getFloat") || !strcmp(mname, "getString") ||
                     !strcmp(mname, "getProperty") || !strcmp(mname, "getProperties") ||
                     !strcmp(mname, "getDeviceConfigPropertyBoolean")) {
                meth_api[m] = DEX_API_DC_STR; has_any_api = 1;
            }
        } else if (pt == 3) {
            if (!strcmp(mname, "getBoolean") || !strcmp(mname, "getInt") ||
                !strcmp(mname, "getLong") || !strcmp(mname, "getFloat") ||
                !strcmp(mname, "getString") || !strcmp(mname, "getBooleanFlagValue") ||
                !strcmp(mname, "getKeyset") || !strcmp(mname, "isEnabled") ||
                !strcmp(mname, "onPropertiesChanged")) {
                meth_api[m] = DEX_API_DC_PROP1; has_any_api = 1;
            }
        } else if (!strncmp(mname, "getDeviceConfigProperty", 23)) {
            if (strstr(mname, "Boolean")) meth_api[m] = DEX_API_DC_BOOL;
            else if (strstr(mname, "Int")) meth_api[m] = DEX_API_DC_INT;
            else if (strstr(mname, "Long")) meth_api[m] = DEX_API_DC_LONG;
            else meth_api[m] = DEX_API_DC_STR;
            has_any_api = 1;
        }
    }
    free(is_prop_type);

    const char **field_prop = field_cnt > 0 ? calloc(field_cnt, sizeof(const char *)) : NULL;
    const uint8_t *dex_end = dex + dex_sz;

    // Проход 1: индексация static_values_off / sput-object и обнаружение R8/ProGuard-обёрток
    for (int hop = 0; hop < 2; hop++) {
        int added_wrappers = 0;
        for (uint32_t c = 0; c < cls_cnt; c++) {
            uint32_t c_type_idx = *(const uint32_t *)(dex + cls_off + c * 32);
            uint32_t cdata_off = *(const uint32_t *)(dex + cls_off + c * 32 + 24);
            uint32_t sval_off = *(const uint32_t *)(dex + cls_off + c * 32 + 28);
            if (!cdata_off || cdata_off >= dex_sz) continue;

            const uint8_t *p = dex + cdata_off;
            uint32_t sf_cnt = read_uleb128(&p, dex_end);
            uint32_t if_cnt = read_uleb128(&p, dex_end);
            uint32_t dm_cnt = read_uleb128(&p, dex_end);
            uint32_t vm_cnt = read_uleb128(&p, dex_end);

            uint32_t sf_idx = 0;
            const uint8_t *svp = (hop == 0 && field_prop && sval_off > 0 && sval_off < dex_sz) ? (dex + sval_off) : NULL;
            uint32_t sv_cnt = svp ? read_uleb128(&svp, dex_end) : 0;

            for (uint32_t i = 0; i < sf_cnt && p < dex_end; i++) {
                sf_idx += read_uleb128(&p, dex_end);
                read_uleb128(&p, dex_end);
                if (svp && i < sv_cnt && svp < dex_end) {
                    uint8_t hdr_b = *svp++;
                    uint8_t vtype = hdr_b & 0x1f;
                    uint8_t varg = (hdr_b >> 5) & 0x7;
                    if (vtype == 0x1e || vtype == 0x1f) {
                        continue;
                    } else if (vtype == 0x17 && svp + varg + 1 <= dex_end) {
                        uint32_t sidx = 0;
                        for (uint8_t b = 0; b <= varg; b++) sidx |= ((uint32_t)svp[b] << (b * 8));
                        svp += varg + 1;
                        if (sf_idx < field_cnt) {
                            size_t slen = 0;
                            const char *s = dex_get_str(dex, dex_sz, str_ids, str_cnt, sidx, &slen);
                            if (s && is_dex_token_str(s, slen)) field_prop[sf_idx] = s;
                        }
                    } else if ((vtype <= 0x06 || (vtype >= 0x10 && vtype <= 0x1b)) && svp + varg + 1 <= dex_end) {
                        svp += varg + 1;
                    } else {
                        svp = NULL;
                    }
                }
            }
            for (uint32_t i = 0; i < if_cnt * 2 && p < dex_end; i++) read_uleb128(&p, dex_end);

            uint32_t total_m = dm_cnt + vm_cnt;
            uint32_t m_id = 0;
            int cls_has_refl_sysprop = 0;

            for (uint32_t m = 0; m < total_m && p < dex_end; m++) {
                if (m == dm_cnt) m_id = 0;
                m_id += read_uleb128(&p, dex_end);
                read_uleb128(&p, dex_end);
                uint32_t code_off = read_uleb128(&p, dex_end);
                if (!code_off || (uint64_t)code_off + 16 > dex_sz || m_id >= meth_cnt) continue;

                uint32_t insns_sz = *(const uint32_t *)(dex + code_off + 12);
                if (!insns_sz || (uint64_t)code_off + 16 + (uint64_t)insns_sz * 2 > dex_sz) continue;
                const uint16_t *insns = (const uint16_t *)(dex + code_off + 16);

                int m_has_cand = 0, m_loads_refl = 0;
                uint8_t called_api = 0;

                for (uint32_t pc = 0; pc < insns_sz; ) {
                    uint16_t inst = insns[pc];
                    uint8_t op = inst & 0xFF;
                    int w = dalvik_insn_width(insns, pc, insns_sz);
                    if (w <= 0 || pc + w > insns_sz) break;

                    if (op == 0x1a || op == 0x1b) {
                        uint32_t sidx = (op == 0x1a) ? insns[pc + 1] : ((uint32_t)insns[pc + 1] | ((uint32_t)insns[pc + 2] << 16));
                        if (str_sysprop_dot >= 0 && sidx == (uint32_t)str_sysprop_dot) {
                            m_loads_refl = 1;
                            cls_has_refl_sysprop = 1;
                        }
                        size_t slen = 0;
                        const char *s = dex_get_str(dex, dex_sz, str_ids, str_cnt, sidx, &slen);
                        if (s) {
                            if (is_dex_prop_cand(s, slen)) m_has_cand = 1;
                            if (hop == 0 && field_prop && op == 0x1a && pc + 2 < insns_sz &&
                                (insns[pc + 2] & 0xFF) == 0x69 && (insns[pc + 2] >> 8) == (inst >> 8)) {
                                uint16_t fidx = insns[pc + 3];
                                if (fidx < field_cnt && is_dex_token_str(s, slen)) field_prop[fidx] = s;
                            }
                        }
                    } else if (((op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78)) && insns[pc + 1] < meth_cnt) {
                        uint8_t ca = meth_api[insns[pc + 1]];
                        if (ca) called_api = ca;
                    }
                    pc += w;
                }

                if (!meth_api[m_id] && !m_has_cand && insns_sz <= 128 && (called_api || m_loads_refl)) {
                    const uint16_t *mid = (const uint16_t *)(dex + meth_off + m_id * 8);
                    int is_dc = (called_api >= DEX_API_DC_BOOL && called_api <= DEX_API_DC_PROP1);
                    uint8_t w_api = dex_proto_to_wrap_api(dex, dex_sz, str_ids, str_cnt, proto_off, proto_cnt, mid[1], str_type_idx, is_dc);
                    if (w_api) {
                        meth_api[m_id] = w_api;
                        has_any_api = 1;
                        added_wrappers = 1;
                    }
                }
            }

            if (cls_has_refl_sysprop && total_m <= 40) {
                for (uint32_t m = 0; m < meth_cnt; m++) {
                    const uint16_t *mid = (const uint16_t *)(dex + meth_off + m * 8);
                    if (mid[0] == c_type_idx && !meth_api[m]) {
                        uint8_t w_api = dex_proto_to_wrap_api(dex, dex_sz, str_ids, str_cnt, proto_off, proto_cnt, mid[1], str_type_idx, 0);
                        if (w_api) {
                            meth_api[m] = w_api;
                            has_any_api = 1;
                            added_wrappers = 1;
                        }
                    }
                }
            }
        }
        if (!added_wrappers) break;
    }

    if (!has_any_api && str_sysprop_dot < 0) {
        if (field_prop) free(field_prop);
        free(meth_api);
        return;
    }

    int64_t val_int[256];
    const char *val_str[256];
    uint8_t has_int[256], has_str[256], is_cand[256];

    for (uint32_t c = 0; c < cls_cnt; c++) {
        uint16_t c_type_idx = *(const uint16_t *)(dex + cls_off + c * 32);
        uint32_t cdata_off = *(const uint32_t *)(dex + cls_off + c * 32 + 24);
        if (!cdata_off || cdata_off >= dex_sz) continue;

        const char *cdesc = (c_type_idx < type_cnt) ? dex_get_str(dex, dex_sz, str_ids, str_cnt, type_ids[c_type_idx], NULL) : NULL;
        if (cdesc && strstr(cdesc, "WritableFlags")) continue;
        int cls_calls_dc = (cdesc && (strstr(cdesc, "Flags;") || strstr(cdesc, "FeatureFlag") ||
                                      strstr(cdesc, "DeviceConfig") || strstr(cdesc, "Aconfig"))) ? 1 : 0;
        int cls_is_setter = 0, cls_calls_getter = 0;

        const uint8_t *p = dex + cdata_off;
        uint32_t sf_cnt = read_uleb128(&p, dex_end);
        uint32_t if_cnt = read_uleb128(&p, dex_end);
        uint32_t dm_cnt = read_uleb128(&p, dex_end);
        uint32_t vm_cnt = read_uleb128(&p, dex_end);

        const uint8_t *p_sfields = p;
        for (uint32_t i = 0; i < (sf_cnt + if_cnt) * 2 && p < dex_end; i++) read_uleb128(&p, dex_end);

        uint32_t total_m = dm_cnt + vm_cnt;
        const uint8_t *p_methods = p;

        // Быстрый предпросмотр класса: определяем cls_calls_dc, cls_calls_getter и cls_is_setter
        uint32_t preview_m_id = 0;
        for (uint32_t m = 0; m < total_m && p < dex_end; m++) {
            if (m == dm_cnt) preview_m_id = 0;
            preview_m_id += read_uleb128(&p, dex_end);
            read_uleb128(&p, dex_end);
            uint32_t code_off = read_uleb128(&p, dex_end);
            if (preview_m_id < meth_cnt && str_on_prop_chg >= 0) {
                const uint16_t *mid = (const uint16_t *)(dex + meth_off + preview_m_id * 8);
                uint32_t n_idx = *(const uint32_t *)(mid + 2);
                if (n_idx == (uint32_t)str_on_prop_chg) cls_calls_dc = 1;
            }
            if (!code_off || (uint64_t)code_off + 16 > dex_sz) continue;
            uint32_t insns_sz = *(const uint32_t *)(dex + code_off + 12);
            if (!insns_sz || (uint64_t)code_off + 16 + (uint64_t)insns_sz * 2 > dex_sz) continue;
            const uint16_t *insns = (const uint16_t *)(dex + code_off + 16);
            for (uint32_t pc = 0; pc < insns_sz; ) {
                uint16_t inst = insns[pc];
                uint8_t op = inst & 0xFF;
                int w = dalvik_insn_width(insns, pc, insns_sz);
                if (w <= 0 || pc + w > insns_sz) break;
                if (((op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78)) && insns[pc + 1] < meth_cnt) {
                    uint16_t midx = insns[pc + 1];
                    uint8_t ma = meth_api[midx];
                    if (ma >= DEX_API_DC_BOOL && ma <= DEX_API_DC_PROP1) { cls_calls_dc = 1; cls_calls_getter = 1; }
                    else if (ma == DEX_API_SET) cls_is_setter = 1;
                    else if (ma != 0) cls_calls_getter = 1;
                }
                pc += w;
            }
        }
        if (cls_calls_getter) cls_is_setter = 0;

        // Выгружаем инлайновые static final String константы класса из field_prop (static_values_off)
        if (field_prop && !cls_is_setter && sf_cnt > 0) {
            const uint8_t *sp = p_sfields;
            uint32_t sf_idx = 0;
            for (uint32_t i = 0; i < sf_cnt && sp < dex_end; i++) {
                sf_idx += read_uleb128(&sp, dex_end);
                read_uleb128(&sp, dex_end);
                if (sf_idx < field_cnt && field_prop[sf_idx]) {
                    const char *fs = field_prop[sf_idx];
                    size_t flen = strlen(fs);
                    if (is_dex_prop_cand(fs, flen)) {
                        fprintf(out, "__DEX_TOKEN__:%s=DYNAMIC_DEFAULT|%s\n", fs, jar_name);
                    } else if (cls_calls_dc) {
                        emit_dex_dc_token(out, fs, flen, jar_name);
                    }
                }
            }
        }

        p = p_methods;
        uint32_t m_id = 0;
        for (uint32_t m = 0; m < total_m && p < dex_end; m++) {
            if (m == dm_cnt) m_id = 0;
            m_id += read_uleb128(&p, dex_end);
            read_uleb128(&p, dex_end);
            uint32_t code_off = read_uleb128(&p, dex_end);
            if (!code_off || (uint64_t)code_off + 16 > dex_sz) continue;

            uint32_t insns_sz = *(const uint32_t *)(dex + code_off + 12);
            if (!insns_sz || (uint64_t)code_off + 16 + (uint64_t)insns_sz * 2 > dex_sz) continue;
            const uint16_t *insns = (const uint16_t *)(dex + code_off + 16);

            // Предпроверка вызовов SystemProperties / perfGetProp + индексация статических строковых полей (sput-object)
            int method_calls_prop = 0, method_calls_setter = 0, method_calls_dc = cls_calls_dc, method_has_prop_str = 0;
            if (m_id < meth_cnt && str_on_prop_chg >= 0) {
                const uint16_t *mid = (const uint16_t *)(dex + meth_off + m_id * 8);
                if (*(const uint32_t *)(mid + 2) == (uint32_t)str_on_prop_chg) method_calls_dc = 1;
            }

            for (uint32_t pc = 0; pc < insns_sz; ) {
                uint16_t inst = insns[pc];
                uint8_t op = inst & 0xFF;
                int w = dalvik_insn_width(insns, pc, insns_sz);
                if (w <= 0 || pc + w > insns_sz) break;
                if (op == 0x1a || op == 0x1b) {
                    uint32_t sidx = (op == 0x1a) ? insns[pc + 1] : ((uint32_t)insns[pc + 1] | ((uint32_t)insns[pc + 2] << 16));
                    size_t slen = 0;
                    const char *s = dex_get_str(dex, dex_sz, str_ids, str_cnt, sidx, &slen);
                    if (s) {
                        if (is_dex_prop_cand(s, slen)) method_has_prop_str = 1;
                        if (field_prop && op == 0x1a && pc + 2 < insns_sz && (insns[pc + 2] & 0xFF) == 0x69 && (insns[pc + 2] >> 8) == (inst >> 8)) {
                            uint16_t fidx = insns[pc + 3];
                            if (fidx < field_cnt && is_dex_prop_cand(s, slen)) field_prop[fidx] = s;
                        }
                    }
                } else if (op == 0x62 && field_prop && insns[pc + 1] < field_cnt && field_prop[insns[pc + 1]]) {
                    method_has_prop_str = 1;
                } else if (((op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78)) && insns[pc + 1] < meth_cnt) {
                    uint16_t midx = insns[pc + 1];
                    uint8_t ma = meth_api[midx];
                    if (ma) {
                        method_calls_prop = 1;
                        if (ma == DEX_API_SET) method_calls_setter = 1;
                        if (ma >= DEX_API_DC_BOOL && ma <= DEX_API_DC_PROP1) method_calls_dc = 1;
                    }
                }
                pc += w;
            }
            if (!method_calls_prop && !method_calls_dc && !method_has_prop_str) continue;

            memset(has_int, 0, sizeof(has_int));
            memset(has_str, 0, sizeof(has_str));
            memset(is_cand, 0, sizeof(is_cand));
            const char *last_dc_ns = NULL;

            for (uint32_t pc = 0; pc < insns_sz; ) {
                uint16_t inst = insns[pc];
                uint8_t op = inst & 0xFF;
                int w = dalvik_insn_width(insns, pc, insns_sz);
                if (w <= 0 || pc + w > insns_sz) break;

                if (op == 0x01) { // move vA, vB
                    uint8_t a = (inst >> 8) & 0xF, b = (inst >> 12) & 0xF;
                    val_int[a] = val_int[b]; has_int[a] = has_int[b]; has_str[a] = 0; is_cand[a] = 0;
                } else if (op == 0x02) { // move/from16 vAA, vBBBB
                    uint8_t a = inst >> 8; uint16_t b = insns[pc + 1];
                    if (b < 256) { val_int[a] = val_int[b]; has_int[a] = has_int[b]; has_str[a] = 0; is_cand[a] = 0; }
                } else if (op == 0x07) { // move-object vA, vB
                    uint8_t a = (inst >> 8) & 0xF, b = (inst >> 12) & 0xF;
                    val_str[a] = val_str[b]; has_str[a] = has_str[b]; is_cand[a] = is_cand[b]; has_int[a] = 0;
                } else if (op == 0x08) { // move-object/from16 vAA, vBBBB
                    uint8_t a = inst >> 8; uint16_t b = insns[pc + 1];
                    if (b < 256) { val_str[a] = val_str[b]; has_str[a] = has_str[b]; is_cand[a] = is_cand[b]; has_int[a] = 0; }
                } else if (op == 0x12) { // const/4
                    uint8_t r = (inst >> 8) & 0xF;
                    val_int[r] = (int8_t)(inst >> 8) >> 4;
                    has_int[r] = 1; has_str[r] = 0; is_cand[r] = 0;
                } else if (op == 0x13 || op == 0x16) { // const/16, const-wide/16
                    uint8_t r = inst >> 8;
                    val_int[r] = (int16_t)insns[pc + 1];
                    has_int[r] = 1; has_str[r] = 0; is_cand[r] = 0;
                } else if (op == 0x14 || op == 0x17) { // const, const-wide/32
                    uint8_t r = inst >> 8;
                    val_int[r] = (int32_t)((uint32_t)insns[pc + 1] | ((uint32_t)insns[pc + 2] << 16));
                    has_int[r] = 1; has_str[r] = 0; is_cand[r] = 0;
                } else if (op == 0x15) { // const/high16
                    uint8_t r = inst >> 8;
                    val_int[r] = (int32_t)((uint32_t)insns[pc + 1] << 16);
                    has_int[r] = 1; has_str[r] = 0; is_cand[r] = 0;
                } else if (op == 0x18) { // const-wide
                    uint8_t r = inst >> 8;
                    uint64_t lo = (uint32_t)insns[pc + 1] | ((uint32_t)insns[pc + 2] << 16);
                    uint64_t hi = (uint32_t)insns[pc + 3] | ((uint32_t)insns[pc + 4] << 16);
                    val_int[r] = (int64_t)(lo | (hi << 32));
                    has_int[r] = 1; has_str[r] = 0; is_cand[r] = 0;
                } else if (op == 0x1a || op == 0x1b) { // const-string, const-string/jumbo
                    uint8_t r = inst >> 8;
                    uint32_t sidx = (op == 0x1a) ? insns[pc + 1] : ((uint32_t)insns[pc + 1] | ((uint32_t)insns[pc + 2] << 16));
                    size_t slen = 0;
                    const char *s = dex_get_str(dex, dex_sz, str_ids, str_cnt, sidx, &slen);
                    if (s) {
                        val_str[r] = s; has_str[r] = 1; has_int[r] = 0;
                        is_cand[r] = is_dex_prop_cand(s, slen) ? 1 : 0;
                        if (!method_calls_setter) {
                            if (is_cand[r]) {
                                fprintf(out, "__DEX_TOKEN__:%s=DYNAMIC_DEFAULT|%s\n", s, jar_name);
                            } else if (method_calls_dc) {
                                emit_dex_dc_token(out, s, slen, jar_name);
                            }
                        }
                    }
                } else if (op == 0x69 && field_prop) { // sput-object vAA, field@BBBB
                    uint8_t r = inst >> 8;
                    uint16_t fidx = insns[pc + 1];
                    if (fidx < field_cnt && has_str[r] && is_cand[r] && val_str[r]) {
                        field_prop[fidx] = val_str[r];
                    }
                } else if (op == 0x62 && field_prop) { // sget-object vAA, field@BBBB
                    uint8_t r = inst >> 8;
                    uint16_t fidx = insns[pc + 1];
                    if (fidx < field_cnt && field_prop[fidx]) {
                        const char *fs = field_prop[fidx];
                        size_t flen = strlen(fs);
                        val_str[r] = fs; has_str[r] = 1; has_int[r] = 0;
                        is_cand[r] = is_dex_prop_cand(fs, flen) ? 1 : 0;
                        if (!method_calls_setter) {
                            if (is_cand[r]) {
                                fprintf(out, "__DEX_TOKEN__:%s=DYNAMIC_DEFAULT|%s\n", fs, jar_name);
                            } else if (method_calls_dc) {
                                emit_dex_dc_token(out, fs, flen, jar_name);
                            }
                        }
                    } else {
                        has_str[r] = 0; has_int[r] = 0; is_cand[r] = 0;
                    }
                } else if (op >= 0x52 && op <= 0x58) {
                    uint8_t r = (inst >> 8) & 0xF;
                    has_str[r] = 0; has_int[r] = 0; is_cand[r] = 0;
                } else if ((op >= 0x0a && op <= 0x0d) || op == 0x22 || (op >= 0x44 && op <= 0x4a) || (op >= 0x60 && op <= 0x66)) {
                    uint8_t r = inst >> 8;
                    has_str[r] = 0; has_int[r] = 0; is_cand[r] = 0;
                }

                if ((op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78)) {
                    uint16_t midx = insns[pc + 1];
                    int n_args = 0; uint8_t args[6] = {0};
                    if (op >= 0x6e && op <= 0x72) {
                        n_args = (inst >> 12) & 0xF;
                        uint16_t w2 = insns[pc + 2];
                        args[0] = w2 & 0xF; args[1] = (w2 >> 4) & 0xF; args[2] = (w2 >> 8) & 0xF;
                        args[3] = (w2 >> 12) & 0xF; args[4] = (inst >> 8) & 0xF;
                    } else {
                        n_args = inst >> 8; if (n_args > 6) n_args = 6;
                        uint16_t r0 = insns[pc + 2];
                        for (int a = 0; a < n_args; a++) args[a] = (uint8_t)((r0 + a) & 0xFF);
                    }

                    uint8_t atype = (midx < meth_cnt) ? meth_api[midx] : 0;
                    if (!atype && !method_calls_setter && n_args >= 1) {
                        const char *cand_p = NULL;
                        for (int a = 0; a < n_args; a++) {
                            if (has_str[args[a]] && is_cand[args[a]]) { cand_p = val_str[args[a]]; break; }
                        }
                        if (cand_p) {
                            atype = check_multidex_static_getter(dex, dex_sz, str_ids, str_cnt, type_ids, type_cnt,
                                                                 proto_off, proto_cnt, meth_off, meth_cnt, midx, str_type_idx, cand_p);
                        }
                    }

                    if (atype) {
                        if (atype >= DEX_API_DC_BOOL && atype <= DEX_API_DC_PROP1) {
                            int ns_pos = (op == 0x71 || op == 0x77) ? 0 : 1;
                            if (atype != DEX_API_DC_PROP1 && n_args > ns_pos + 1 &&
                                has_str[args[ns_pos]] && val_str[args[ns_pos]] &&
                                has_str[args[ns_pos + 1]] && val_str[args[ns_pos + 1]]) {
                                const char *ns = val_str[args[ns_pos]];
                                const char *fl = val_str[args[ns_pos + 1]];
                                if (is_dex_token_str(ns, strlen(ns)) && is_dex_token_str(fl, strlen(fl))) {
                                    last_dc_ns = ns;
                                    char dc_pname[256];
                                    snprintf(dc_pname, sizeof(dc_pname), "persist.device_config.%s.%s", ns, fl);
                                    if (atype == DEX_API_DC_BOOL) {
                                        int is_t = (n_args > ns_pos + 2 && has_int[args[ns_pos + 2]] && val_int[args[ns_pos + 2]] == 1);
                                        fprintf(out, "%s=%s|%s\n", dc_pname, is_t ? "DEFAULT_TRUE" : "DEFAULT_FALSE", jar_name);
                                    } else if (atype == DEX_API_DC_INT || atype == DEX_API_DC_LONG) {
                                        long long dv = (n_args > ns_pos + 2 && has_int[args[ns_pos + 2]]) ? (long long)val_int[args[ns_pos + 2]] : 0;
                                        fprintf(out, "%s=DEFAULT_INT: %lld|%s\n", dc_pname, dv, jar_name);
                                    } else {
                                        if (n_args > ns_pos + 2 && has_str[args[ns_pos + 2]] && val_str[args[ns_pos + 2]]) {
                                            fprintf(out, "%s=DEFAULT_STR: \"%s\"|%s\n", dc_pname, val_str[args[ns_pos + 2]], jar_name);
                                        } else {
                                            fprintf(out, "%s=DYNAMIC_DEFAULT|%s\n", dc_pname, jar_name);
                                        }
                                    }
                                    emit_dex_dc_token(out, fl, strlen(fl), jar_name);
                                }
                            } else {
                                for (int a = 0; a < n_args; a++) {
                                    if (has_str[args[a]] && val_str[args[a]]) {
                                        const char *fl = val_str[args[a]];
                                        size_t fl_len = strlen(fl);
                                        if (is_dex_token_str(fl, fl_len)) {
                                            if (a == ns_pos && atype != DEX_API_DC_PROP1) {
                                                last_dc_ns = fl;
                                            }
                                            if (fl_len >= 10 && (strchr(fl, '_') || strchr(fl, '-') || strchr(fl, '.'))) {
                                                if (last_dc_ns && strcmp(last_dc_ns, fl) != 0) {
                                                    char dc_pname[256];
                                                    snprintf(dc_pname, sizeof(dc_pname), "persist.device_config.%s.%s", last_dc_ns, fl);
                                                    if (atype == DEX_API_DC_BOOL) {
                                                        int is_t = (n_args > a + 1 && has_int[args[a + 1]] && val_int[args[a + 1]] == 1);
                                                        fprintf(out, "%s=%s|%s\n", dc_pname, is_t ? "DEFAULT_TRUE" : "DEFAULT_FALSE", jar_name);
                                                    } else if (atype == DEX_API_DC_INT || atype == DEX_API_DC_LONG) {
                                                        long long dv = (n_args > a + 1 && has_int[args[a + 1]]) ? (long long)val_int[args[a + 1]] : 0;
                                                        fprintf(out, "%s=DEFAULT_INT: %lld|%s\n", dc_pname, dv, jar_name);
                                                    } else {
                                                        if (n_args > a + 1 && has_str[args[a + 1]] && val_str[args[a + 1]]) {
                                                            fprintf(out, "%s=DEFAULT_STR: \"%s\"|%s\n", dc_pname, val_str[args[a + 1]], jar_name);
                                                        } else {
                                                            fprintf(out, "%s=DYNAMIC_DEFAULT|%s\n", dc_pname, jar_name);
                                                        }
                                                    }
                                                }
                                                emit_dex_dc_token(out, fl, fl_len, jar_name);
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            int k_pos = (atype == DEX_API_PERF && n_args >= 2) ? 1 : 0;
                            if (!has_str[args[k_pos]] || !is_cand[args[k_pos]]) {
                                for (int a = 0; a < n_args; a++) {
                                    if (has_str[args[a]] && is_cand[args[a]]) { k_pos = a; break; }
                                }
                            }
                            if (n_args > k_pos) {
                                uint8_t kreg = args[k_pos];
                                if (has_str[kreg] && is_cand[kreg] && val_str[kreg]) {
                                    const char *pname = val_str[kreg];
                                    int d_pos = k_pos + 1;
                                    if (atype == DEX_API_SET) {
                                        fprintf(out, "%s=DYNAMIC_SETTER|%s\n", pname, jar_name);
                                    } else if (atype == DEX_API_BOOL) {
                                        int is_t = (n_args > d_pos && has_int[args[d_pos]] && val_int[args[d_pos]] == 1);
                                        fprintf(out, "%s=%s|%s\n", pname, is_t ? "DEFAULT_TRUE" : "DEFAULT_FALSE", jar_name);
                                    } else if (atype == DEX_API_INT || atype == DEX_API_LONG) {
                                        long long dv = (n_args > d_pos && has_int[args[d_pos]]) ? (long long)val_int[args[d_pos]] : 0;
                                        fprintf(out, "%s=DEFAULT_INT: %lld|%s\n", pname, dv, jar_name);
                                    } else if (atype == DEX_API_PERF) {
                                        int perf_d = (n_args >= 3) ? 2 : 1;
                                        if (n_args > perf_d && has_str[args[perf_d]] && val_str[args[perf_d]]) {
                                            const char *ds = val_str[args[perf_d]];
                                            if (!strcmp(ds, "false")) fprintf(out, "%s=DEFAULT_FALSE|%s\n", pname, jar_name);
                                            else if (!strcmp(ds, "true")) fprintf(out, "%s=DEFAULT_TRUE|%s\n", pname, jar_name);
                                            else fprintf(out, "%s=DEFAULT_STR: \"%s\"|%s\n", pname, ds, jar_name);
                                        } else fprintf(out, "%s=DYNAMIC_DEFAULT|%s\n", pname, jar_name);
                                    } else if (atype == DEX_API_STR2 && n_args > d_pos) {
                                        uint8_t dreg = args[d_pos];
                                        if (has_str[dreg] && val_str[dreg]) fprintf(out, "%s=DEFAULT_STR: \"%s\"|%s\n", pname, val_str[dreg], jar_name);
                                        else fprintf(out, "%s=DYNAMIC_DEFAULT|%s\n", pname, jar_name);
                                    } else if (atype == DEX_API_STR1) {
                                        fprintf(out, "%s=DEFAULT_STR: \"\"|%s\n", pname, jar_name);
                                    } else {
                                        fprintf(out, "%s=DYNAMIC_DEFAULT|%s\n", pname, jar_name);
                                    }
                                }
                            }
                        }
                    }
                }
                pc += w;
            }
        }
    }
    if (field_prop) free(field_prop);
    free(meth_api);
}

static void *dex_worker(void *arg) {
    (void)arg;
    while (1) {
        int idx = __sync_fetch_and_add(&g_next_dex_task, 1);
        if (idx >= g_dex_task_cnt) break;
        DexTask *t = &g_dex_tasks[idx];
        uint8_t *decomp = NULL;
        const uint8_t *dex_ptr = NULL;
        size_t dex_sz = t->uncomp_sz;

        if (t->method == 0) {
            if ((uint64_t)t->comp_off + t->uncomp_sz <= t->zip_size) dex_ptr = t->zip_data + t->comp_off;
        } else if (t->method == 8 && t->uncomp_sz > 0 && (uint64_t)t->comp_off + t->comp_sz <= t->zip_size) {
            decomp = malloc(t->uncomp_sz);
            if (decomp) {
                z_stream strm = {0};
                strm.next_in = (Bytef *)(t->zip_data + t->comp_off);
                strm.avail_in = t->comp_sz;
                strm.next_out = decomp;
                strm.avail_out = t->uncomp_sz;
                if (inflateInit2(&strm, -MAX_WBITS) == Z_OK) {
                    if (inflate(&strm, Z_FINISH) == Z_STREAM_END) dex_ptr = decomp;
                    inflateEnd(&strm);
                }
            }
        }
        if (dex_ptr) {
            size_t bsz = 0;
            FILE *mem = open_memstream(&t->out_buf, &bsz);
            if (mem) {
                parse_dex_buffer(dex_ptr, dex_sz, t->jar_name, mem);
                fclose(mem);
            }
        }
        if (decomp) free(decomp);
        if (t->map_ref && __sync_sub_and_fetch(t->map_ref, 1) == 0) {
            munmap((void *)t->zip_data, t->zip_size);
            free(t->map_ref);
        }
    }
    return NULL;
}

static inline uint16_t r16(const void *p) {
    uint16_t v; memcpy(&v, p, 2); return v;
}
static inline uint32_t r32(const void *p) {
    uint32_t v; memcpy(&v, p, 4); return v;
}

// Поиск несжатых секций dex\n03x\0 внутри .vdex контейнера (zero-copy без zlib)
static int queue_vdex_sections(const uint8_t *vdata, size_t vsz, const char *jname, size_t *tcap) {
    if (vsz < 128 || memcmp(vdata, "vdex", 4) != 0) return 0;
    int added = 0;
    int *ref = malloc(sizeof(int));
    if (!ref) return 0;
    *ref = 0;

    for (size_t off = 16; off + 112 <= vsz; off += 4) {
        if (vdata[off] == 'd' && vdata[off + 1] == 'e' && vdata[off + 2] == 'x' && vdata[off + 3] == '\n' &&
            vdata[off + 4] == '0' && vdata[off + 7] == '\0') {
            uint32_t d_sz = r32(vdata + off + 32);
            uint32_t h_sz = r32(vdata + off + 36);
            if (h_sz == 112 && d_sz >= 112 && (uint64_t)off + d_sz <= vsz) {
                if ((size_t)g_dex_task_cnt >= *tcap) {
                    *tcap *= 2;
                    g_dex_tasks = realloc(g_dex_tasks, (*tcap) * sizeof(DexTask));
                }
                (*ref)++;
                g_dex_tasks[g_dex_task_cnt++] = (DexTask){vdata, vsz, (uint32_t)off, d_sz, d_sz, 0, jname, NULL, ref};
                added++;
                off += ((d_sz + 3) & ~3u) - 4;
            }
        }
    }
    if (added == 0) free(ref);
    return added;
}

int main(int argc, char **argv) {
    if (argc == 2 && (!strcmp(argv[1], "-v") || !strcmp(argv[1], "--version"))) {
        printf("overridify-scan %s\n", SCANNER_VERSION); return 0;
    }
    if (argc >= 3 && !strcmp(argv[1], "--dex")) {
        memset(g_seen_ino, 0, sizeof(g_seen_ino));
        size_t tcap = 128;
        g_dex_tasks = calloc(tcap, sizeof(DexTask));
        for (int a = 2; a < argc; a++) {
            const char *path = argv[a];
            int fd = open(path, O_RDONLY); if (fd < 0) continue;
            struct stat st;
            if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size < 22) { close(fd); continue; }
            uint64_t ino_key = ((uint64_t)st.st_dev << 32) ^ (uint64_t)st.st_ino;
            if (ino_key) {
                uint32_t ih = (uint32_t)(ino_key ^ (ino_key >> 17)) & 16383;
                int dup = 0;
                for (int probe = 0; probe < 16384; probe++) {
                    if (g_seen_ino[ih] == ino_key) { dup = 1; break; }
                    if (g_seen_ino[ih] == 0) { g_seen_ino[ih] = ino_key; break; }
                    ih = (ih + 1) & 16383;
                }
                if (dup) { close(fd); continue; }
            }
            const char *jname = strrchr(path, '/'); jname = jname ? jname + 1 : path;
            if (!strcmp(jname, "base.apk") && jname > path) {
                const char *s2 = jname - 1;
                while (s2 > path && *(s2 - 1) != '/') s2--;
                size_t dlen = (size_t)(jname - 1 - s2);
                const char *dash = memchr(s2, '-', dlen);
                if (dash && (size_t)(dash - s2) < 250) {
                    size_t plen = (size_t)(dash - s2);
                    char *dj = malloc(plen + 5);
                    if (dj) {
                        snprintf(dj, plen + 5, "%.*s.apk", (int)plen, s2);
                        jname = dj;
                    }
                }
            }

            // Fast-path: проверяем парный oat/arm64/<stem>.vdex (zero-copy без декомпрессии + поддержка stripped/odex APK)
            const char *raw_name = strrchr(path, '/');
            raw_name = raw_name ? raw_name + 1 : path;
            const char *ext = strrchr(raw_name, '.');
            if (ext && (!strcmp(ext, ".apk") || !strcmp(ext, ".jar")) && raw_name > path) {
                char vdex_path[1024];
                size_t dir_len = (size_t)(raw_name - path);
                size_t stem_len = (size_t)(ext - raw_name);
                if (dir_len + stem_len + 20 < sizeof(vdex_path)) {
                    snprintf(vdex_path, sizeof(vdex_path), "%.*soat/arm64/%.*s.vdex",
                             (int)dir_len, path, (int)stem_len, raw_name);
                    int vfd = open(vdex_path, O_RDONLY);
                    if (vfd >= 0) {
                        struct stat vst;
                        if (fstat(vfd, &vst) == 0 && S_ISREG(vst.st_mode) && vst.st_size >= 128) {
                            size_t vsz = (size_t)vst.st_size;
                            const uint8_t *vdata = mmap(NULL, vsz, PROT_READ, MAP_SHARED, vfd, 0);
                            close(vfd);
                            if (vdata != MAP_FAILED) {
                                if (queue_vdex_sections(vdata, vsz, jname, &tcap) > 0) {
                                    close(fd);
                                    continue;
                                }
                                munmap((void *)vdata, vsz);
                            }
                        } else {
                            close(vfd);
                        }
                    }
                }
            }

            if (st.st_size < 112) { close(fd); continue; }
            size_t sz = (size_t)st.st_size;
            const uint8_t *data = mmap(NULL, sz, PROT_READ, MAP_SHARED, fd, 0);
            close(fd);
            if (data == MAP_FAILED) continue;

            if (!memcmp(data, "dex\n", 4)) {
                int *ref = malloc(sizeof(int));
                if (!ref) { munmap((void *)data, sz); continue; }
                *ref = 1;
                if ((size_t)g_dex_task_cnt >= tcap) { tcap *= 2; g_dex_tasks = realloc(g_dex_tasks, tcap * sizeof(DexTask)); }
                g_dex_tasks[g_dex_task_cnt++] = (DexTask){data, sz, 0, (uint32_t)sz, (uint32_t)sz, 0, jname, NULL, ref};
                continue;
            }
            if (!memcmp(data, "vdex", 4)) {
                if (queue_vdex_sections(data, sz, jname, &tcap) == 0) munmap((void *)data, sz);
                continue;
            }
            // Поиск End of Central Directory (PK\x05\x06) в конце ZIP (.jar / .apk)
            size_t scan_back = sz > 65557 ? 65557 : sz;
            const uint8_t *eocd = NULL;
            for (size_t back = 22; back <= scan_back; back++) {
                const uint8_t *p = data + sz - back;
                if (p[0] == 'P' && p[1] == 'K' && p[2] == 5 && p[3] == 6) { eocd = p; break; }
            }
            if (!eocd) { munmap((void*)data, sz); continue; }
            uint16_t cd_cnt = r16(eocd + 10);
            uint32_t cd_off = r32(eocd + 16);
            if ((uint64_t)cd_off >= sz) { munmap((void*)data, sz); continue; }
            const uint8_t *cd = data + cd_off, *end = data + sz;
            int before_cnt = g_dex_task_cnt;
            int *ref = malloc(sizeof(int));
            if (!ref) { munmap((void*)data, sz); continue; }
            *ref = 0;

            for (uint16_t e = 0; e < cd_cnt && cd + 46 <= end; e++) {
                if (cd[0] != 'P' || cd[1] != 'K' || cd[2] != 1 || cd[3] != 2) break;
                uint16_t meth = r16(cd + 10);
                uint32_t c_sz = r32(cd + 20);
                uint32_t u_sz = r32(cd + 24);
                uint16_t fn_len = r16(cd + 28);
                uint16_t ex_len = r16(cd + 30);
                uint16_t cm_len = r16(cd + 32);
                uint32_t lhdr_off = r32(cd + 42);
                const char *fn = (const char *)(cd + 46);

                if (cd + 46 + fn_len <= end && fn_len >= 11 && !strncmp(fn, "classes", 7) && !strncmp(fn + fn_len - 4, ".dex", 4)) {
                    if ((uint64_t)lhdr_off + 30 <= sz && data[lhdr_off] == 'P' && data[lhdr_off + 1] == 'K') {
                        const uint8_t *lhdr = data + lhdr_off;
                        uint16_t l_fn = r16(lhdr + 26);
                        uint16_t l_ex = r16(lhdr + 28);
                        uint32_t data_off = lhdr_off + 30 + l_fn + l_ex;
                        if ((uint64_t)data_off + c_sz <= sz) {
                            if ((size_t)g_dex_task_cnt >= tcap) { tcap *= 2; g_dex_tasks = realloc(g_dex_tasks, tcap * sizeof(DexTask)); }
                            (*ref)++;
                            g_dex_tasks[g_dex_task_cnt++] = (DexTask){data, sz, data_off, c_sz, u_sz, meth, jname, NULL, ref};
                        }
                    }
                }
                cd += 46 + fn_len + ex_len + cm_len;
            }
            if (g_dex_task_cnt == before_cnt) {
                free(ref);
                munmap((void*)data, sz);
            }
        }
        if (g_dex_task_cnt > 0) {
            pthread_t th[NUM_THREADS]; int nt = g_dex_task_cnt < NUM_THREADS ? g_dex_task_cnt : NUM_THREADS;
            for (int t = 0; t < nt; t++) pthread_create(&th[t], NULL, dex_worker, NULL);
            for (int t = 0; t < nt; t++) pthread_join(th[t], NULL);
            for (int i = 0; i < g_dex_task_cnt; i++) {
                if (g_dex_tasks[i].out_buf) { fputs(g_dex_tasks[i].out_buf, stdout); free(g_dex_tasks[i].out_buf); }
            }
        }
        return 0;
    }
    if (argc >= 4 && !strcmp(argv[1], "-f")) {
        FILE *fp = fopen(argv[2], "r"); if (!fp) return 1;
        size_t cap = 512;
        g_radar_pats = malloc(cap * sizeof(char*));
        g_radar_strict = malloc(cap * sizeof(int));
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\r\n")] = 0; if (!line[0]) continue;
            if ((size_t)g_radar_cnt >= cap) {
                cap *= 2;
                g_radar_pats = realloc(g_radar_pats, cap * sizeof(char*));
                g_radar_strict = realloc(g_radar_strict, cap * sizeof(int));
            }
            if (!strncmp(line, "STRICT|", 7)) {
                g_radar_strict[g_radar_cnt] = 1;
                g_radar_pats[g_radar_cnt++] = strdup(line + 7);
            } else {
                g_radar_strict[g_radar_cnt] = 0;
                g_radar_pats[g_radar_cnt++] = strdup(line);
            }
        }
        fclose(fp);
        if (!g_radar_cnt) return 0;
        g_radar_hsize = 1; while (g_radar_hsize < g_radar_cnt * 4) g_radar_hsize <<= 1;
        g_radar_ht = malloc(g_radar_hsize * sizeof(int)); memset(g_radar_ht, -1, g_radar_hsize * sizeof(int));
        g_radar_alive = calloc(g_radar_cnt, sizeof(int));
        for (int i = 0; i < g_radar_cnt; i++) {
            uint32_t h = fnv1a(g_radar_pats[i]) & (g_radar_hsize - 1);
            while (g_radar_ht[h] != -1) h = (h + 1) & (g_radar_hsize - 1);
            g_radar_ht[h] = i;
        }
        g_files = &argv[3]; g_num_files = argc - 3;
        pthread_t th[NUM_THREADS]; int nt = g_num_files < NUM_THREADS ? g_num_files : NUM_THREADS;
        for (int t = 0; t < nt; t++) pthread_create(&th[t], NULL, mt_worker, (void*)1);
        for (int t = 0; t < nt; t++) pthread_join(th[t], NULL);
        for (int i = 0; i < g_radar_cnt; i++) if (g_radar_alive[i]) printf("%s\n", g_radar_pats[i]);
        return 0;
    }
    int arg_off = 1, rflags = REG_EXTENDED | REG_NOSUB;
    if (argc >= 4 && !strcmp(argv[1], "-i")) { rflags |= REG_ICASE; arg_off = 2; g_is_search = 1; }
    if (argc < arg_off + 2) return 1;
    if (strcmp(argv[arg_off], ".") == 0) g_is_all = 1;
    else if (regcomp(&g_regex, argv[arg_off], rflags) == 0) g_use_regex = 1;
    g_files = &argv[arg_off + 1]; g_num_files = argc - (arg_off + 1);
    g_file_out = calloc(g_num_files, sizeof(char*));
    pthread_t th[NUM_THREADS]; int nt = g_num_files < NUM_THREADS ? g_num_files : NUM_THREADS;
    for (int t = 0; t < nt; t++) pthread_create(&th[t], NULL, mt_worker, (void*)0);
    for (int t = 0; t < nt; t++) pthread_join(th[t], NULL);
    for (int i = 0; i < g_num_files; i++) {
        if (g_file_out[i]) { fputs(g_file_out[i], stdout); free(g_file_out[i]); }
    }
    free(g_file_out);
    if (g_use_regex) regfree(&g_regex);
    return 0;
}