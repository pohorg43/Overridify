/*
 * mali-patcher: Automated AArch64 binary scanner and patcher for ARM Mali vkGetDeviceQueue2 driver bug.
 * Developed for Overridify.
 * Compatible with Magisk, KernelSU, APatch, NoMount, and Mountify.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <dirent.h>

#define OP_LDRB_W8_X1_10 0x39404028
#define OP_MASK_TBNZ_W8  0xfff8001f
#define OP_MATCH_TBNZ_W8 0x37000008
#define OP_STR_XZR_X2    0xf900005f
#define OP_RET           0xd65f03c0
#define OP_NOP           0xd503201f

static void store_resolved_path(const char *path, char *out_path, size_t max_len) {
    char resolved[1024];
    if (realpath(path, resolved)) {
        snprintf(out_path, max_len, "%s", resolved);
    } else {
        snprintf(out_path, max_len, "%s", path);
    }
}

// Universal Zero-Hardcode resolver for libGLES_mali.so across partitions and SoC subfolders
static int find_mali_driver(char *out_path, size_t max_len) {
    const char *egl_dirs[] = {
        "/vendor/lib64/egl",
        "/odm/lib64/egl",
        NULL
    };

    // 1. Direct check (realpath automatically resolves symlinks to any mtXXXX / arm subfolder)
    for (int i = 0; egl_dirs[i]; i++) {
        char direct[1024];
        snprintf(direct, sizeof(direct), "%s/libGLES_mali.so", egl_dirs[i]);
        if (access(direct, R_OK) == 0) {
            store_resolved_path(direct, out_path, max_len);
            return 0;
        }
    }

    // 2. Dynamic directory and 1-level subdirectory scan
    for (int i = 0; egl_dirs[i]; i++) {
        DIR *d = opendir(egl_dirs[i]);
        if (!d) continue;

        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (de->d_name[0] == '.') continue;

            char full[1024];
            snprintf(full, sizeof(full), "%s/%s", egl_dirs[i], de->d_name);

            struct stat st;
            if (stat(full, &st) != 0) continue;

            if (S_ISREG(st.st_mode) && strstr(de->d_name, "mali") && strstr(de->d_name, ".so")) {
                closedir(d);
                store_resolved_path(full, out_path, max_len);
                return 0;
            }

            if (S_ISDIR(st.st_mode)) {
                DIR *sd = opendir(full);
                if (!sd) continue;
                struct dirent *sde;
                while ((sde = readdir(sd)) != NULL) {
                    if (sde->d_name[0] == '.') continue;
                    if (strstr(sde->d_name, "mali") && strstr(sde->d_name, ".so")) {
                        char sub_full[1024];
                        snprintf(sub_full, sizeof(sub_full), "%s/%s", full, sde->d_name);
                        if (access(sub_full, R_OK) == 0) {
                            closedir(sd);
                            closedir(d);
                            store_resolved_path(sub_full, out_path, max_len);
                            return 0;
                        }
                    }
                }
                closedir(sd);
            }
        }
        closedir(d);
    }
    return -1;
}

// Scans driver binary for vkGetDeviceQueue2 bug signature.
// Returns:
//   1 -> BUG_FOUND (needs patch)
//   2 -> ALREADY_PATCHED
//   0 -> CLEAN / NOT_FOUND
//  -1 -> Error opening/reading file
static int scan_driver(const char *path, uint64_t *out_offset, int *out_state, uint32_t *out_op1) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < 128) { close(fd); return -1; }
    
    size_t sz = st.st_size;
    const uint32_t *data = (const uint32_t *)mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (data == MAP_FAILED) return -1;
    
    size_t n_words = sz / 4;
    int found = 0;
    
    for (size_t i = 0; i + 4 < n_words; i++) {
        if (data[i] == OP_LDRB_W8_X1_10) {
            uint32_t op1 = data[i+1];
            uint32_t op2 = data[i+2];
            uint32_t op3 = data[i+3];
            
            if (op2 == OP_STR_XZR_X2 && op3 == OP_RET) {
                if ((op1 & OP_MASK_TBNZ_W8) == OP_MATCH_TBNZ_W8) {
                    if (out_offset) *out_offset = (uint64_t)i * 4;
                    if (out_state) *out_state = 1; // BUG_FOUND
                    if (out_op1) *out_op1 = op1;
                    found = 1;
                    break;
                } else if ((op1 & 0xfc000000) == 0x14000000) { // b <target>
                    if (out_offset) *out_offset = (uint64_t)i * 4;
                    if (out_state) *out_state = 2; // ALREADY_PATCHED
                    if (out_op1) *out_op1 = op1;
                    found = 2;
                    break;
                }
            }
        }
    }
    
    munmap((void*)data, sz);
    return found;
}

// Copy file via atomic temporary file
static int safe_copy_file(const char *src, const char *dst, char *out_tmp, size_t max_tmp_len) {
    struct stat st_src;
    if (stat(src, &st_src) != 0 || st_src.st_size == 0) {
        fprintf(stderr, "[-] Error: Source driver %s is invalid or empty\n", src);
        return -1;
    }

    // Create parent directories if needed
    char path_copy[1024];
    strncpy(path_copy, dst, sizeof(path_copy) - 1);
    path_copy[sizeof(path_copy) - 1] = '\0';
    for (char *p = path_copy + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(path_copy, 0755);
            *p = '/';
        }
    }

    snprintf(out_tmp, max_tmp_len, "%s.tmp.%d", dst, (int)getpid());
    unlink(out_tmp);

    int in = open(src, O_RDONLY);
    if (in < 0) return -2;

    int out = open(out_tmp, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (out < 0) {
        close(in);
        return -3;
    }

    char buf[131072];
    ssize_t n;
    size_t total_written = 0;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        ssize_t w = write(out, buf, n);
        if (w != n) {
            close(in);
            close(out);
            unlink(out_tmp);
            return -4;
        }
        total_written += (size_t)w;
    }
    close(in);
    fsync(out);
    close(out);

    if (total_written != (size_t)st_src.st_size) {
        unlink(out_tmp);
        return -5;
    }

    return 0;
}

// Patches src into dst
static int patch_driver(const char *src, const char *dst) {
    uint64_t off = 0;
    int state = 0;
    uint32_t op1 = 0;
    
    int scan_rc = scan_driver(src, &off, &state, &op1);
    if (scan_rc < 0) {
        fprintf(stderr, "[-] Error: Failed to read source driver %s\n", src);
        return 1;
    }
    if (state == 2) {
        struct stat st_src, st_dst;
        if (stat(src, &st_src) == 0 && stat(dst, &st_dst) == 0) {
            if (st_src.st_dev == st_dst.st_dev && st_src.st_ino == st_dst.st_ino) {
                fprintf(stderr, "[*] Driver is already patched and active at %s\n", dst);
                return 0;
            }
        }
        char tmp_file[1024];
        if (safe_copy_file(src, dst, tmp_file, sizeof(tmp_file)) != 0) {
            fprintf(stderr, "[-] Error: Failed to copy %s to temporary file\n", src);
            return 2;
        }
        if (rename(tmp_file, dst) != 0) {
            unlink(tmp_file);
            fprintf(stderr, "[-] Error: Failed to atomic rename to %s\n", dst);
            return 2;
        }
        chmod(dst, 0644);
        fprintf(stderr, "[+] Copied patched driver to %s\n", dst);
        return 0;
    }
    if (state != 1) {
        fprintf(stderr, "[-] Error: Buggy opcode pattern not found in %s\n", src);
        return 3;
    }
    
    fprintf(stderr, "[+] Found buggy vkGetDeviceQueue2 opcode at 0x%lx (op1=0x%08x)\n", off, op1);
    char tmp_file[1024];
    if (safe_copy_file(src, dst, tmp_file, sizeof(tmp_file)) != 0) {
        fprintf(stderr, "[-] Error: Failed to copy %s to temporary file\n", src);
        return 4;
    }
    
    int fd = open(tmp_file, O_RDWR);
    if (fd < 0) {
        unlink(tmp_file);
        fprintf(stderr, "[-] Error: Failed to open %s for writing\n", tmp_file);
        return 5;
    }
    
    struct stat st_tmp;
    if (fstat(fd, &st_tmp) != 0) {
        close(fd);
        unlink(tmp_file);
        return 5;
    }

    // In tbnz: imm14 is bits 18:5 (signed offset in words)
    int32_t imm14 = (op1 >> 5) & 0x3fff;
    if (imm14 & 0x2000) imm14 |= ~0x1fff; // sign extend

    int64_t target_off_signed = (int64_t)off + 4 + ((int64_t)imm14 * 4);
    if (target_off_signed < 0 || (uint64_t)(target_off_signed + 0x18) > (uint64_t)st_tmp.st_size) {
        close(fd);
        unlink(tmp_file);
        fprintf(stderr, "[-] Error: Computed branch target 0x%llx is out of bounds\n", (unsigned long long)target_off_signed);
        return 6;
    }
    uint64_t target_off = (uint64_t)target_off_signed;

    // Branch instruction: b <target> (0x14000000 | (imm14 & 0x03ffffff))
    uint32_t b_op = 0x14000000 | (imm14 & 0x03ffffff);
    uint32_t nop = OP_NOP;

    // Write b_op at off + 4 and NOP 3 instructions at target_off + 0xc..0x14
    if (pwrite(fd, &b_op, 4, off + 4) != 4 ||
        pwrite(fd, &nop, 4, target_off + 0xc) != 4 ||
        pwrite(fd, &nop, 4, target_off + 0x10) != 4 ||
        pwrite(fd, &nop, 4, target_off + 0x14) != 4) {
        close(fd);
        unlink(tmp_file);
        return 6;
    }

    fsync(fd);
    close(fd);
    
    // Verification of temporary file before replacing dst
    uint64_t v_off = 0;
    int v_state = 0;
    if (scan_driver(tmp_file, &v_off, &v_state, NULL) <= 0 || v_state != 2) {
        unlink(tmp_file);
        fprintf(stderr, "[-] Verification failed for patched binary\n");
        return 7;
    }

    struct stat st_v;
    if (stat(tmp_file, &st_v) != 0 || st_v.st_size == 0) {
        unlink(tmp_file);
        fprintf(stderr, "[-] Patched binary is empty\n");
        return 8;
    }

    // Atomic replace
    if (rename(tmp_file, dst) != 0) {
        unlink(tmp_file);
        fprintf(stderr, "[-] Failed to atomically replace %s\n", dst);
        return 9;
    }

    chmod(dst, 0644);
    fprintf(stderr, "[+] Successfully verified and installed patched binary %s at 0x%lx!\n", dst, v_off);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("mali-patcher (Overridify ARM64 Driver Utility)\n");
        printf("Usage:\n");
        printf("  mali-patcher find                - Prints path of detected Mali driver\n");
        printf("  mali-patcher status [path]       - Returns 1 if BUG_FOUND, 2 if PATCHED, 0 if CLEAN\n");
        printf("  mali-patcher patch <src> <dst>   - Copies and patches driver to dst\n");
        return 0;
    }

    if (strcmp(argv[1], "find") == 0) {
        char path[1024];
        if (find_mali_driver(path, sizeof(path)) == 0) {
            printf("%s\n", path);
            return 0;
        }
        return 1;
    }

    if (strcmp(argv[1], "status") == 0) {
        char path[1024];
        const char *target = NULL;
        if (argc >= 3) {
            target = argv[2];
        } else {
            if (find_mali_driver(path, sizeof(path)) == 0) {
                target = path;
            } else {
                printf("NOT_MALI\n");
                return 0;
            }
        }
        
        uint64_t off = 0;
        int state = 0;
        int rc = scan_driver(target, &off, &state, NULL);
        if (rc < 0) {
            printf("ERR_READ\n");
            return 3;
        }
        if (state == 1) {
            printf("BUG_FOUND 0x%lx\n", off);
            return 1;
        } else if (state == 2) {
            printf("ALREADY_PATCHED 0x%lx\n", off);
            return 2;
        } else {
            printf("CLEAN\n");
            return 0;
        }
    }

    if (strcmp(argv[1], "patch") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: mali-patcher patch <src> <dst>\n");
            return 1;
        }
        return patch_driver(argv[2], argv[3]);
    }

    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    return 1;
}
