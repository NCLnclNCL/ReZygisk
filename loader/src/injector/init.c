#include <stdbool.h>
#include <stdarg.h>
#include <errno.h>
#include <asm-generic/fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <linux/un.h>
#include <sys/socket.h>

#include "raw_syscalls.h"

/*
 * INFO: Things in this file will be ran in a state where this .so is not properly loaded.
 * Library functions must not be called, raw syscalls must be used instead.
 * Other essential things are also not working, like TLS or relocations.
 */


/*
 * INFO: visibility("default") must not be used, as it makes accesses go through the GOT,
 * which is not supported due to the aforementioned reasons of half-assed .so loading.
 */
#define EXPORT __attribute__((visibility("protected")))

#define DCL_HOOK_FUNC(ret, func, ...)         \
  EXPORT ret (*init_old_##func)(__VA_ARGS__); \
  EXPORT ret init_new_##func(__VA_ARGS__)

EXPORT volatile bool init_is_unhooked;

static int init_sock;
static struct sockaddr_un init_sock_addr = {
        .sun_family = AF_UNIX,
        .sun_path = "/data/adb/nrezygisk/init_con.sock\0"
};

DCL_HOOK_FUNC(pid_t, fork) {
    if (init_is_unhooked || raw_gettid() != 1) {
        return init_old_fork();
    }

    char dummy = 0;
    int pipefd[2] = {-1};
    raw_pipe2(pipefd, O_CLOEXEC);

    pid_t new_pid = init_old_fork();

    if (new_pid == 0) {
        raw_close(pipefd[1]);
        raw_read_n(pipefd[0], &dummy, 1);
        raw_close(pipefd[0]);
        raw_close(init_sock);
    } else {
        raw_close(pipefd[0]);
        raw_write_n(init_sock, &new_pid, sizeof(new_pid));
        raw_read_n(init_sock, &dummy, 1);
        raw_write_n(pipefd[1], &dummy, 1);
        raw_close(pipefd[1]);
    }

    return new_pid;
}

static int init_fork_pipe[2];

static void init_atfork_prepare() {
    init_fork_pipe[0] = -1;
    if (init_is_unhooked || raw_gettid() != 1) return;
    raw_pipe2(init_fork_pipe, O_CLOEXEC);
}

static void init_atfork_parent() {
    if (init_fork_pipe[0] < 0) return;
    raw_close(init_fork_pipe[0]);

    char dummy;
    raw_read_n(init_sock, &dummy, 1);
    raw_write_n(init_fork_pipe[1], &dummy, 1);
    raw_close(init_fork_pipe[1]);
}

static void init_atfork_child() {
    if (init_fork_pipe[0] < 0) return;
    raw_close(init_fork_pipe[1]);

    pid_t new_pid = raw_gettid();
    raw_write_n(init_sock, &new_pid, sizeof(new_pid));
    raw_close(init_sock);

    char dummy;
    raw_read_n(init_fork_pipe[0], &dummy, 1);
    raw_close(init_fork_pipe[0]);
}

EXPORT int init_entry(void (*pthread_atfork)(void*, void*, void*)) {
    int sockets[2];
    long r = raw_socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets);
    if (r < 0) {
        return 1000 - r;
    }

    long socket = raw_socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (socket < 0) {
        return 2000 - socket;
    }

    r = raw_connect(socket, &init_sock_addr, sizeof(init_sock_addr));
    if (r < 0) {
        return 3000 - r;
    }

    r = raw_send_fd(socket, sockets[1]);
    if (r < 0) {
        return 4000 - r;
    }

    raw_close(sockets[1]);
    raw_close(socket);

    if (pthread_atfork) {
        init_is_unhooked = false;
        pthread_atfork(init_atfork_prepare, init_atfork_parent, init_atfork_child);
    } else {
        init_is_unhooked = true;
    }

    init_sock = sockets[0];
    init_old_fork = 0;

    return 42;
}