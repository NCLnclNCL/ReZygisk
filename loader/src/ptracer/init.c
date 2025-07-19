#include <stddef.h>
#include <string.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/un.h>
#include <linux/prctl.h>

#include "utils.h"
#include "breakpoint.h"
#include "monitor.h"
#include "elf_util.h"
#include "socket_utils.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunknown-pragmas"
#pragma ide diagnostic ignored "ConstantParameter"

void* elfplt_init(uintptr_t base_addr);
void* elfplt_addr(void *v_elf, const char *name);

bool init_injected = false;
bool init_hooked = false;

/* INFO: Start address of libzygisk.so in our address space */
static void *lib_local_base;
/* INFO: Start address of libzygisk.so in init address space */
static void *lib_init_base;
/* INFO: Address (in init addr space) of the libzygisk.so variable that can disable the hooks */
static void *lib_init_is_unhooked;

/* INFO: Address where we mapped /system/bin/init into our address space */
static void *exe_local_base;
/* INFO: Start address of /system/bin/init in init address space */
static void *exe_init_base;
/* INFO: Address of pthread_atfork in init address space */
static void *exe_pthread_atfork;

/* INFO: Socket where our init hook will send events to us */
int init_sock = -1;

static const char *lib_path = TMP_PATH "/lib" LP_SELECT("", "64") "/libzygisk.so";
static const char *disable_path = TMP_PATH "/bad_init_inject";

/* INFO: lsplt Elf of /system/bin/init (see plt.cpp) */
static void *elfplt_exe;
/* INFO: ElfImg of libzygisk.so */
static ElfImg *elf_lib;

static bool init_set_syscall_reg(pid_t pid, struct user_regs_struct *regs, long nr) {
    regs->REG_SYSNR = nr;
#if defined(__aarch64__)
    int sysnr = (int) nr;
    struct iovec iov = {
        .iov_base = &sysnr,
        .iov_len = sizeof (int),
    };
    ptrace(PTRACE_SETREGSET, pid, NT_ARM_SYSTEM_CALL, &iov);
#elif defined(__arm__)
    ptrace(PTRACE_SET_SYSCALL, pid, 0, (void*) nr);
#endif

    return set_regs(pid, regs);
}

static void init_wait_for_syscall(const char *tag, int line, pid_t pid) {
    while (true) {
        int status;
        wait_for_trace(pid, &status, __WALL);

        if (!WIFSTOPPED(status) || WSTOPSIG(status) != (SIGTRAP | 0x80)) {
            char status_str[64];
            parse_status(status, status_str, sizeof(status_str));
            PLOGE("init_wait_for_syscall @ %s/%d: unexpected status %s", tag, line, status_str);
            long resume = WIFSTOPPED(status) ? WSTOPSIG(status) : 0;
            if (ptrace(PTRACE_SYSCALL, pid, 0, resume) == -1) {
                exit(1);
            }
            continue;
        }

        return;
    }
}

static void init_cont_to_syscall(const char *tag, int line, pid_t pid) {
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
        PLOGE("init_cont_to_syscall @ %s/%d: ptrace(PTRACE_SYSCALL, %d)", tag, line, pid);
        exit(1);
    }
}

#define CONT_TO_SYSCALL(pid) init_cont_to_syscall(__func__, __LINE__, pid)
#define WAIT_FOR_SYSCALL(pid) init_wait_for_syscall(__func__, __LINE__, pid)
#define STEP_SYSCALL(pid) CONT_TO_SYSCALL(pid); WAIT_FOR_SYSCALL(pid)


/*
 * INFO: Makes the tracee perform a syscall.
 * This must be called in a syscall enter stop.
 * On return, tracee will again be in a syscall enter stop.
 */
static long
init_syscall(pid_t pid, struct user_regs_struct *oregs, long nr, long a0, long a1, long a2, long a3,
             long a4, long a5) {
    struct user_regs_struct regs = *oregs;
#if defined(__x86_64__)
    regs.rdi = a0;
    regs.rsi = a1;
    regs.rdx = a2;
    regs.r10 = a3;
    regs.r8 = a4;
    regs.r9 = a5;
#elif defined(__i386__)
    regs.ebx = a0;
    regs.ecx = a1;
    regs.edx = a2;
    regs.esi = a3;
    regs.edi = a4;
    regs.ebp = a5;
#elif defined(__aarch64__)
    regs.regs[0] = a0;
    regs.regs[1] = a1;
    regs.regs[2] = a2;
    regs.regs[3] = a3;
    regs.regs[4] = a4;
    regs.regs[5] = a5;
#elif defined(__arm__)
    regs.uregs[0] = a0;
    regs.uregs[1] = a1;
    regs.uregs[2] = a2;
    regs.uregs[3] = a3;
    regs.uregs[4] = a4;
    regs.uregs[5] = a5;
#endif

    /* INFO: We are in syscall enter stop, so set syscall number and run sycall */
    if (!init_set_syscall_reg(pid, &regs, nr)) {
        PLOGE("init_syscall: init_set_syscall_reg(%d, &regs, %ld)", pid, nr);
        exit(1);
    }
    STEP_SYSCALL(pid);

    /* INFO: In syscall exit stop, get return value */
    if (!get_regs(pid, &regs)) {
        PLOGE("init_syscall: get_regs(%d, &regs)", pid);
        exit(1);
    }

    /* INFO: Restore original registers */
    /* INFO: Thanks to this, a simple PTRACE_CONT can resume normal execution of init */
    if (!set_regs(pid, oregs)) {
        PLOGE("init_syscall: set_regs(%d, oregs)", pid);
        exit(1);
    }
    STEP_SYSCALL(pid);
    /* INFO: As original ip points to syscall insn, we should now be back at syscall enter stop */

#if defined(__x86_64__)
    return regs.rax;
#elif defined(__i386__)
    return regs.eax;
#elif defined(__aarch64__)
    return regs.regs[0];
#elif defined(__arm__)
    return regs.uregs[0];
#endif
}

/* INFO: Interrupt the tracee and bring it into syscall entry stop */
static void init_to_sys_entry(pid_t pid, struct user_regs_struct *oregs) {
    int status;
    if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) == -1) {
        PLOGE("init_to_sys_entry: ptrace(PTRACE_INTERRUPT)");
        exit(1);
    }
    wait_for_trace(pid, &status, __WALL);

    STEP_SYSCALL(pid);

    if (!get_regs(pid, oregs)) {
        PLOGE("init_to_sys_entry: get_regs(%d, oregs)", pid);
        exit(1);
    }

    if (oregs->REG_SYSNR == __NR_restart_syscall) {
        /* INFO: Resume the syscall and try to abort it */
        CONT_TO_SYSCALL(pid);
        /* INFO: This might abort the syscall with EINTR */
        kill(pid, SIGCHLD);
        WAIT_FOR_SYSCALL(pid);

        /* INFO: We are now in syscall exit stop, so we wait until syscall enter stop */
        STEP_SYSCALL(pid);

        if (!get_regs(pid, oregs)) {
            PLOGE("init_to_sys_entry: get_regs(%d, oregs)", pid);
            exit(1);
        }
    }

    /* INFO: The ip points to the insn after the syscall insn, move it back to the syscall insn */
    oregs->REG_IP -= SYSCALL_LEN(oregs);
}

/* INFO: Returns the address of the PLT entry of the given function (in init address space) */
static void *init_exe_plt(const char *name) {
    if (!elfplt_exe || !exe_local_base || !exe_init_base) return NULL;
    unsigned long local = (unsigned long) elfplt_addr(elfplt_exe, name);
    if (!local) return NULL;
    return (void *) (local - (unsigned long) exe_local_base + (unsigned long) exe_init_base);
}

/* INFO: Returns the address of the given libzygisk.so symbol (in init address space) */
static void *init_lib_symbol(const char *name) {
    if (!elf_lib || !lib_local_base || !lib_init_base) return NULL;
    unsigned long local = getSymbAddress(elf_lib, name);
    if (!local) return NULL;
    return (void *) (local - (unsigned long) lib_local_base + (unsigned long) lib_init_base);
}

/* INFO: Hook the PLT of a single function in init */
static bool init_apply_hook(const char *exe_name, const char *lib_name, const char *lib_old_name) {
    /* INFO: PLT address of the function we want to hook */
    void *plt = init_exe_plt(exe_name);

    /* INFO: The hook function in libzygisk.so (init.c) */
    void *lib = init_lib_symbol(lib_name);

    /* INFO: The variable in libzygisk.so (init.c) where we put the original function address */
    void *lib_old = init_lib_symbol(lib_old_name);

    if (!plt || !lib || !lib_old) {
        LOGE("init_apply_hook: %s = %p, %s = %p, %s = %p", exe_name, plt, lib_name, lib,
             lib_old_name, lib_old);
        return false;
    }

    void *plt_orig = 0;
    if (read_proc(1, (uintptr_t) plt, &plt_orig, sizeof(plt_orig)) != sizeof(plt_orig)) {
        return false;
    }

    if (write_proc(1, (uintptr_t) lib_old, &plt_orig, sizeof(plt_orig)) != sizeof(plt_orig)) {
        PLOGE("init_apply_hook: write_proc(lib_old: %p)", lib_old);
        return false;
    }

    if (ptrace(PTRACE_POKEDATA, 1, plt, lib) == -1) {
        PLOGE("init_apply_hook: ptrace(PTRACE_POKEDATA, plt: %p)", plt);
        return false;
    }

    return true;
}

/* INFO: Place the PLT hooks into init */
static void init_apply_hooks() {
    lib_init_is_unhooked = init_lib_symbol("init_is_unhooked");
    if (!lib_init_is_unhooked) {
        LOGE("init_inject: missing init_is_unhooked symbol");
        return;
    }

    init_hooked = true;

    if (exe_pthread_atfork) {
        /* INFO: pthread_atfork method is used instead of PLT hook for statically linked init */
        return;
    }

#define APPLY_INIT_HOOK(n) if (!init_apply_hook(#n, "init_new_" #n, "init_old_" #n)) init_hooked = false;
    APPLY_INIT_HOOK(fork)
#undef APPLY_INIT_HOOK


    bool is_unhooked = !init_hooked;
    write_proc(1, (uintptr_t) lib_init_is_unhooked, &is_unhooked, sizeof(is_unhooked));
}

static bool init_map_lib() {
    int lib_fd = open(lib_path, O_RDONLY | O_CLOEXEC);
    if (lib_fd < 0) {
        PLOGE("init_map_lib: open(%s)", lib_path);
        return false;
    }

    struct stat st;
    if (fstat(lib_fd, &st) != 0) {
        PLOGE("init_map_lib: fstat(%s)", lib_path);
        return false;
    }

    lib_local_base = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, lib_fd, 0);
    close(lib_fd);

    elf_lib = ElfImg_create(lib_path, lib_local_base);
    if (!elf_lib) {
        PLOGE("init_map_lib: ElfImg_create(lib_path)");
        return false;
    }

    return true;
}

static bool init_map_exe() {
    exe_local_base = NULL;
    exe_init_base = NULL;
    exe_pthread_atfork = NULL;

    char exe_path[128];
    ssize_t ps = readlink("/proc/1/exe", exe_path, sizeof(exe_path) - 1);
    if (ps < 0) {
        PLOGE("init_map_exe: readlink(/proc/1/exe)");
        return false;
    }
    exe_path[ps] = 0;

    struct maps *init_maps = parse_maps("/proc/1/maps");
    if (!init_maps) {
        PLOGE("init_map_exe: parse_maps(/proc/1/maps)");
        return false;
    }

    for (size_t i = 0; i < init_maps->size; ++i) {
        struct map *m = &init_maps->maps[i];
        if (m->offset == 0 && strcmp(m->path, exe_path) == 0) {
            exe_init_base = (void *) m->start;
            break;
        }
    }

    free_maps(init_maps);

    if (!exe_init_base) {
        LOGE("init_map_exe: couldn't find %s in /proc/1/maps", exe_path);
        return false;
    }

    int exe_fd = open("/proc/1/exe", O_RDONLY | O_CLOEXEC);
    if (exe_fd < 0) {
        PLOGE("init_map_exe: open(/proc/1/exe)");
        return false;
    }

    struct stat st;
    if (fstat(exe_fd, &st) == -1) {
        PLOGE("init_map_exe: fstat(/proc/1/exe)");
        return false;
    }

    exe_local_base = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, exe_fd, 0);
    close(exe_fd);

    if (exe_local_base == MAP_FAILED) {
        PLOGE("init_map_exe: mmap");
        exe_local_base = NULL;
        return false;
    }

    elfplt_exe = elfplt_init((uintptr_t) exe_local_base);
    if (elfplt_exe) {
        return true;
    }

    PLOGE("init_map_exe: elfplt_init(exe_local_base)");

    ElfImg *elf_exe = ElfImg_create("/proc/1/exe", exe_init_base);
    if (!elf_exe) {
        PLOGE("init_map_exe: ELfImg_create");
        return false;
    }

    ElfImg *debug_exe = ElfImg_loadGnuDebugdata(elf_exe);
    if (!debug_exe) {
        PLOGE("init_map_exe: ElfImg_loadGnuDebugdata");
        ElfImg_destroy(elf_exe);
        return false;
    }

    exe_pthread_atfork = (void *) getSymbAddress(debug_exe, "pthread_atfork");
    if (!exe_pthread_atfork) {
        PLOGE("init_map_exe: getSymbAddress(pthread_atfork)");
        ElfImg_destroy(elf_exe);
        return false;
    }

    ElfImg_destroy(elf_exe);
    return true;
}

static struct sockaddr_un init_sock_addr = {
        .sun_family = AF_UNIX,
        .sun_path = "/data/adb/nrezygisk/init_con.sock\0"
};

static int chcon(const char *restrict path, const char *context) {
    char command[PATH_MAX];
    snprintf(command, sizeof(command), "chcon %s %s", context, path);

    return system(command);
}

static bool init_call_entry(struct user_regs_struct *oregs) {
    void *entry = init_lib_symbol("init_entry");
    if (!entry) {
        LOGE("init_call_entry: missing init_entry symbol");
        return false;
    }

    int server_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (server_fd < 0) {
        PLOGE("init_call_entry: socket");
        return false;
    }

    unlink(init_sock_addr.sun_path);

    if (bind(server_fd, (const struct sockaddr *) &init_sock_addr, sizeof(init_sock_addr)) == -1) {
        PLOGE("init_call_entry: bind");
        return false;
    }

    if (chcon(init_sock_addr.sun_path, "u:object_r:zygisk_file:s0") == -1) {
        PLOGE("init_call_entry: chcon");
        return false;
    }

    struct user_regs_struct regs = *oregs;

    /* INFO: To respect red zone */
    regs.REG_SP -= 256;

    /* INFO: We are in syscall enter stop, set syscall number to -1 to skip syscall */
    if (!init_set_syscall_reg(1, &regs, -1)) {
        PLOGE("init_call_entry: init_set_syscall_reg");
        exit(1);
    }
    STEP_SYSCALL(1);

    long args[1];
    args[0] = (long) exe_pthread_atfork;
    int ret = (int) remote_call(1, &regs, (uintptr_t) entry, 0, args, 1);

    /* INFO: Now we restore the registers and return to syscall enter stop */
    if (!set_regs(1, oregs)) {
        PLOGE("init_call_entry: get_regs(1, oregs)");
        exit(1);
    }
    STEP_SYSCALL(1);

    if (ret != 42) {
        LOGE("init_call_entry: entry returned %d", ret);
        return false;
    }

    init_sock = read_fd(server_fd);
    if (init_sock <= 0) {
        PLOGE("init_call_entry: read_fd");
        return false;
    }
    close(server_fd);
    unlink(init_sock_addr.sun_path);

    fcntl(init_sock, F_SETFL, fcntl(init_sock, F_GETFL) | O_NONBLOCK);
    fcntl(init_sock, F_SETFD, fcntl(init_sock, F_GETFD) | FD_CLOEXEC);

    return true;
}

static void init_elf_size(ElfImg *img, size_t *out_size, size_t *out_min) {
    size_t min_addr = ~0;
    size_t max_addr = 0;
    size_t align = sysconf(_SC_PAGE_SIZE);
    ElfW(Phdr) *phdr = (ElfW(Phdr) *)((uintptr_t)img->header + img->header->e_phoff);
    for (int i = 0; i < img->header->e_phnum; ++i) {
        ElfW(Phdr) *h = &phdr[i];
        if (h->p_type == PT_LOAD) {
            size_t start = h->p_vaddr & ~(align - 1);
            size_t end = (h->p_vaddr + h->p_memsz + align - 1) & ~(align - 1);

            if (start < min_addr) min_addr = start;
            if (end > max_addr) max_addr = end;
        }
    }

    *out_size = max_addr - min_addr;
    *out_min = min_addr;
}

static void* init_elf_map_remote(pid_t pid, struct user_regs_struct *oregs, ElfImg *img) {

#define REMOTE_SYSCALL(n, a, b, c, d, e, f) ({\
    long _r = init_syscall(pid, oregs, n, (long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f));\
    if (((unsigned long)(_r) >= (unsigned long)(-4095)) && n != SYS_prctl) {\
        LOGE("init_elf_map_remote (%d): " #n "() = %ld", __LINE__, _r);\
        return NULL;\
    }\
    _r; })

#ifdef SYS_mmap
#define REMOTE_MMAP(a, b, c, d, e, f) REMOTE_SYSCALL(SYS_mmap, a, b, c, d, e, f)
#else
#define REMOTE_MMAP(a, b, c, d, e, f) REMOTE_SYSCALL(SYS_mmap2, a, b, c, d, e, (f) / 4096)
#endif

    size_t remote_path = REMOTE_MMAP(0, PATH_MAX, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    write_proc(pid, remote_path, img->elf, strlen(img->elf) + 1);

    long fd = REMOTE_SYSCALL(SYS_openat, AT_FDCWD, remote_path, O_RDONLY | O_CLOEXEC, 0, 0, 0);

    size_t so_size;
    size_t so_min;
    init_elf_size(img, &so_size, &so_min);

    size_t align = sysconf(_SC_PAGE_SIZE);
    size_t so_addr = REMOTE_MMAP(0, so_size + align * 4, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);

    write_proc(pid, remote_path, "zygisk", strlen("zygisk") + 1);
    REMOTE_SYSCALL(SYS_prctl, PR_SET_VMA, PR_SET_VMA_ANON_NAME, so_addr, so_size + align * 4, remote_path, 0);

    ElfW(Phdr) *phdr = (ElfW(Phdr) *)((uintptr_t)img->header + img->header->e_phoff);
    for (int f = 0; f <= 1; ++f) {
        for (int i = 0; i < img->header->e_phnum; ++i) {
            ElfW(Phdr) *h = &phdr[i];
            if (h->p_type == PT_LOAD) {
                long perms = 0;
                if (h->p_flags & PF_R) perms |= PROT_READ;
                if (h->p_flags & PF_W) perms |= PROT_WRITE;
                if (h->p_flags & PF_X) perms |= PROT_EXEC;

                long flags = MAP_FIXED | MAP_PRIVATE;
                size_t start = (h->p_vaddr & ~(align - 1)) + so_addr - so_min;
                size_t pad = h->p_vaddr - (h->p_vaddr & ~(align - 1));

                if (!f && h->p_memsz > h->p_filesz) {
                    REMOTE_MMAP(start, h->p_memsz + pad, perms, flags | MAP_ANON, -1, 0);

                    write_proc(pid, remote_path, ".bss", strlen(".bss") + 1);
                    REMOTE_SYSCALL(SYS_prctl, PR_SET_VMA, PR_SET_VMA_ANON_NAME, start, h->p_memsz + pad, remote_path, 0);
                }

                if (f && h->p_filesz > 0) {
                    size_t sz = h->p_filesz < h->p_memsz ? h->p_filesz : h->p_memsz;
                    REMOTE_MMAP(start, sz + pad, perms, flags, fd, h->p_offset & ~(align - 1));
                }
            }
        }
    }

    REMOTE_SYSCALL(SYS_munmap, remote_path, PATH_MAX, 0, 0, 0, 0);
    REMOTE_SYSCALL(SYS_close, fd, 0, 0, 0, 0, 0);
    return (void *) so_addr;
}

void init_inject() {
    if (access(TMP_PATH "/inject_init", F_OK) != 0) {
        return;
    }

    if (access(disable_path, F_OK) == 0) {
        return;
    }

    /* INFO: Create file that disables init injection, we will delete it if things go well */
    FILE *disable_file = fopen(disable_path, "a");
    if (!fopen(disable_path, "a")) {
        PLOGE("init_inject: fopen(%s)", disable_path);
        return;
    }
    fclose(disable_file);

    if (!init_map_lib() || !init_map_exe()) return;

    /* INFO: Bring init to syscall enter stop and back up original registers */
    struct user_regs_struct oregs;
    init_to_sys_entry(1, &oregs);

    /* INFO: Map libzygisk.so into address space of init */
    lib_init_base = init_elf_map_remote(1, &oregs, elf_lib);
    if (!lib_init_base) {
        ptrace(PTRACE_CONT, 1, 0, 0);
        return;
    }

    if (!init_call_entry(&oregs)) {
        ptrace(PTRACE_CONT, 1, 0, 0);
        return;
    }

    init_apply_hooks();
    init_injected = true;
    if (init_hooked) {
        /* INFO: We can now detach from init, we will be notified of children through init_sock */
        ptrace(PTRACE_DETACH, 1, 0, 0);
    } else {
        ptrace(PTRACE_CONT, 1, 0, 0);
    }
}

void init_went_well() {
    if (init_injected) {
        unlink(disable_path);
    }
}

bool init_resume_hooks() {
    if (!init_hooked) return false;

    bool new = false;
    if (write_proc(1, (uintptr_t) lib_init_is_unhooked, &new, sizeof(new)) != sizeof(new)) {
        PLOGE("init_resume_hooks: write_proc");
        init_hooked = false;
        return false;
    }

    return true;
}

void init_suspend_hooks() {
    if (!init_hooked) return;

    bool new = true;
    write_proc(1, (uintptr_t) lib_init_is_unhooked, &new, sizeof(new));
}

#pragma clang diagnostic pop