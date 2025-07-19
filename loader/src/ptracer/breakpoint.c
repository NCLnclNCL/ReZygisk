
#include <stddef.h>
#include <string.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>

#include "utils.h"
#include "breakpoint.h"
#include "monitor.h"

static void *setexeccon_addr = 0;
static void *execve_addr = 0;

void attr_hook_fork_init(struct init_fork *proc) {
    proc->pid = 0;
    proc->next_breakpoint = 0;
    proc->old_data = 0;
    proc->restore_regs = 0;
    proc->stop = -1;
}

void attr_hook_fork_free(struct init_fork *proc) {
    if (proc->restore_regs) {
        free(proc->restore_regs);
    }
    attr_hook_fork_init(proc);
}

void attr_hook_fork_realloc(struct init_fork **procs, size_t old_len, size_t new_len) {
    for (size_t i = new_len; i < old_len; ++i) {
        attr_hook_fork_free(&(*procs)[i]);
    }
    *procs = realloc(*procs, sizeof(struct init_fork) * new_len);
    for (size_t i = old_len; i < new_len; ++i) {
        attr_hook_fork_init(&(*procs)[i]);
    }
}

static void *attr_hook_map_fun(struct maps *init_maps, const char *lib, const char *fun) {
    size_t lib_len = strlen(lib);

    for (size_t i = 0; i < init_maps->size; ++i) {
        struct map *map = &init_maps->maps[i];
        if (!map->path) continue;
        size_t path_len = strlen(map->path);
        if (path_len > lib_len && strcmp(map->path + (path_len - lib_len), lib) == 0) {
            void *my_map = NULL;
            size_t my_size = (size_t)(map->end - map->start);
            int fd = open(map->path, O_RDONLY | O_CLOEXEC);
            if (!fd) {
                PLOGE("attr_hook_map_fun: can't open %s", map->path);
                return NULL;
            }
            my_map = mmap(NULL, my_size, PROT_READ, MAP_PRIVATE, fd, (off_t) map->offset);
            close(fd);
            if (!my_map) {
                PLOGE("attr_hook_map_fun: can't map %s", map->path);
                return NULL;
            }
            struct maps *my_maps = parse_maps("/proc/self/maps");
            void *addr = find_func_addr(my_maps, init_maps, map->path, fun);
            free_maps(my_maps);
            munmap(my_map, my_size);
            if (!addr) {
                LOGE("attr_hook_map_fun: can't find %s address in %s", fun, map->path);
                return NULL;
            }
            return addr;
        }
    }
    LOGE("attr_hook_map_fun: failed to find %s with %s", lib, fun);
    return NULL;
}

void attr_hook_prepare(void) {
    setexeccon_addr = 0;
    execve_addr = 0;

#if !defined(__aarch64__)
    LOGE("attr_hook_prepare: not aarch64");
    return;
#endif

    if (access(TMP_PATH "/clean_zygote", F_OK) != 0) {
        return;
    }

    struct maps *init_maps = parse_maps("/proc/1/maps");
    if (!init_maps) {
        LOGE("attr_hook_prepare: parse_maps failed");
        return;
    }

    setexeccon_addr = attr_hook_map_fun(init_maps, "/libselinux.so", "setexeccon");
    execve_addr = attr_hook_map_fun(init_maps, "/libc.so", "execve");

    if (!setexeccon_addr || !execve_addr) {
        setexeccon_addr = execve_addr = NULL;
    }

    free_maps(init_maps);
}

#if defined(__x86_64__) || defined(__i386__)
#define TRAP_INS 0xCC
#define TRAP_INS_LEN 1
#elif defined(__aarch64__)
#define TRAP_INS 0xD4200000
#define TRAP_INS_LEN 4
#elif defined(__arm__)
#define TRAP_INS 0xE1200070
#define TRAP_INS_LEN 4
#endif

static void attr_hook_breakpoint(struct init_fork *proc, void *bp_addr) {
    int pid = proc->pid;
    errno = 0;
    long old = ptrace(PTRACE_PEEKTEXT, pid, bp_addr, 0);
    if (old == -1 && errno != 0) {
        PLOGE("attr_hook_breakpoint: ptrace(PTRACE_PEEKTEXT, %d, %p)", pid, bp_addr);
        setexeccon_addr = 0;
        return;
    }
    proc->old_data = old;

    if (ptrace(PTRACE_POKETEXT, pid, bp_addr, (void*) TRAP_INS) == -1) {
        PLOGE("attr_hook_breakpoint: ptrace(PTRACE_POKETEXT, %d, %p, %p)", pid, bp_addr, (void*) TRAP_INS);
        setexeccon_addr = 0;
        return;
    }

    proc->next_breakpoint = bp_addr;
}

static bool enable_new_bp = true;

void attr_hook_place_first_breakpoint(struct init_fork *proc) {
    if (!setexeccon_addr || !execve_addr || !enable_new_bp) return;

    attr_hook_breakpoint(proc, execve_addr);
}

static const char expected32[] = "/system/bin/app_process32";
static const char expected64[] = "/system/bin/app_process64";

bool attr_hook_is_injectable(struct init_fork *proc, const char *path) {
    if (proc->stop != -1) return proc->stop ? 0 : 1;

    if (strncmp(path, expected32, sizeof(expected32)) == 0) {
        if (should_stop_inject32()) {
            proc->stop = 1;
            return false;
        } else {
            proc->stop = 0;
            return true;
        }
    }

    if (strncmp(path, expected64, sizeof(expected64)) == 0) {
        if (should_stop_inject64()) {
            proc->stop = 1;
            return false;
        } else {
            proc->stop = 0;
            return true;
        }
    }

    return false;
}

bool attr_hook_handle(struct init_fork *proc) {
    if (!setexeccon_addr || !execve_addr) {
        return false;
    }

    int pid = proc->pid;

    LOGD("attr_hook_handle: hooking %d", pid);

    struct user_regs_struct regs;
    if (!get_regs(pid, &regs)) {
        LOGE("attr_hook_handle: get_regs(%d, %p) failed", pid, &regs);
        setexeccon_addr = 0;
        if (ptrace(PTRACE_CONT, pid, 0, (void*) SIGSEGV) == -1) {
            PLOGE("attr_hook_handle: last-ditch");
        }
        return true;
    }

    if (!proc->next_breakpoint || ((void*) regs.REG_IP) != proc->next_breakpoint) {
        return false;
    }

    void *breakpoint = proc->next_breakpoint;
    proc->next_breakpoint = NULL;

    if (ptrace(PTRACE_POKETEXT, pid, breakpoint, (void*) proc->old_data) == -1) {
        PLOGE("attr_hook_handle: ptrace(PTRACE_POKETEXT, %d, %p, %p)", pid, breakpoint, (void*) proc->old_data);
        setexeccon_addr = 0;
        if (ptrace(PTRACE_CONT, pid, 0, (void*) SIGSEGV) == -1) {
            PLOGE("attr_hook_handle: last-ditch");
        }
        return true;
    }

    if (proc->restore_regs) {
        if (!set_regs(pid, proc->restore_regs)) {
            LOGE("attr_hook_handle: set_regs(%d, %p) for restore", pid, proc->restore_regs);
            setexeccon_addr = 0;
            if (ptrace(PTRACE_CONT, pid, 0, (void*) SIGSEGV) == -1) {
                PLOGE("attr_hook_handle: last-ditch");
            }
        } else if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
            PLOGE("attr_hook_handle: ptrace(PTRACE_CONT, %d)", pid);
            setexeccon_addr = 0;
        }
        free(proc->restore_regs);
        proc->restore_regs = NULL;
        return true;
    }

    if(breakpoint != execve_addr) {
        LOGE("attr_hook_handle: impossible state %p of pid %d", breakpoint, pid);
        setexeccon_addr = 0;
        if (ptrace(PTRACE_CONT, pid, 0, (void*) SIGSEGV) == -1) {
            PLOGE("attr_hook_handle: last-ditch");
        }
        return true;
    }

#if defined(__x86_64__)
    void *arg = (void*) regs.rdi;
    void *ret_addr = 0;
    read_proc(pid, (uintptr_t) regs.REG_SP, &ret_addr, sizeof(ret_addr));
#elif defined(__i386__)
    void *arg = 0;
    read_proc(pid, (uintptr_t) regs.REG_SP + sizeof(long), &arg, sizeof(arg));
    void *ret_addr = 0;
    read_proc(pid, (uintptr_t) regs.REG_SP, &ret_addr, sizeof(ret_addr));
#elif defined(__aarch64__)
    void *arg = (void*) regs.regs[0];
    void *ret_addr = (void*) regs.regs[30];
#elif defined(__arm__)
    void *arg = (void*) regs.uregs[0];
    void *ret_addr = (void*) regs.uregs[14];
#endif

    char actual[sizeof(expected32)];

    if (read_proc(pid, (uintptr_t) arg, actual, sizeof(actual)) != (ssize_t) sizeof(actual)) {
        PLOGE("attr_hook_handle: read_proc(%d, %p, %p, %d)", pid, arg, &actual, (int) sizeof(actual));
    } else if (attr_hook_is_injectable(proc, actual)) {
        struct user_regs_struct *backup = malloc(sizeof(struct user_regs_struct));
        memcpy(backup, &regs, sizeof(struct user_regs_struct));
        proc->restore_regs = backup;

        const char *con = "u:r:init:s0";
        const uintptr_t remote_con = push_string(pid, &regs, con);
#if defined(__x86_64__)
        regs.rdi = (long) remote_con;
        regs.REG_SP -= sizeof(long);
        write_proc(pid, (uintptr_t) regs.REG_SP, &ret_addr, sizeof(ret_addr));
#elif defined(__i386__)
        regs.REG_SP -= sizeof(long);
        write_proc(pid, (uintptr_t) regs.REG_SP, &remote_con, sizeof(remote_con));
        regs.REG_SP -= sizeof(long);
        write_proc(pid, (uintptr_t) regs.REG_SP, &ret_addr, sizeof(ret_addr));
#elif defined(__aarch64__)
        regs.regs[0] = (long) remote_con;
#elif defined(__arm__)
        regs.uregs[0] = (long) remote_con;
#endif

        attr_hook_breakpoint(proc, ret_addr);
        regs.REG_IP = (long) setexeccon_addr;
        set_regs(pid, &regs);
    }

    LOGD("attr_hook_handle: continuing %d", pid);

    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
        PLOGE("attr_hook_handle: ptrace(PTRACE_CONT, %d)", pid);
        setexeccon_addr = 0;
    }

    return true;
}

void attr_hook_bad_status() {
    enable_new_bp = false;
}