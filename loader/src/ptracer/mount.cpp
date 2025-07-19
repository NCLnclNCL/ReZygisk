#include <unistd.h>
#include <cstring>
#include <fcntl.h>
#include <sched.h>
#include <cstdio>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cerrno>
#include <iostream>
#include <string>
#include <vector>
#include <unordered_set>

#include "utils.h"
#include "daemon.h"
#include "umount.hpp"
#include "rules.hpp"

static void set_process_name(char **argv, const char *name) {
    prctl(PR_SET_NAME, name);
    if (!argv || !argv[0]) return;
    size_t orig_len = strlen(argv[0]);
    argv[0][0] = 0;
    strncat(argv[0], name, orig_len);
}

static bool mount_make_ns() {
    if (unshare(CLONE_NEWNS) == -1) {
        PLOGE("mount_make_ns: unshare(CLONE_NEWNS)");
        return false;
    }

    mount(nullptr, "/", nullptr, MS_REC | MS_SLAVE, nullptr);
    return true;
}

static void mount_save_ns(const char *save) {
    char path[64];
    int pid = getpid();
    int fd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
    snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, fd);

    unlink(save);
    symlink(path, save);
}

static pid_t mount_spawn_ns(char **argv, const char *pname, const char *save) {
    int ready_pipe[2] = {-1, -1};
    pipe(ready_pipe);

    pid_t pid = fork();
    if (pid == 0) {
        close(ready_pipe[0]);
        set_process_name(argv, pname);

        if (!mount_make_ns()) {
            _exit(0);
        }

        mount_save_ns(save);

        close(ready_pipe[1]);
        while (pause());
    }

    close(ready_pipe[1]);
    char dummy;
    TEMP_FAILURE_RETRY(read(ready_pipe[0], &dummy, 1));
    return pid;
}

extern "C" void mount_ns_private() {
    if (access(TMP_PATH "/private_mounts", F_OK) != 0) {
        return;
    }

    rules_reload();

    DIR *proc = opendir("/proc");
    if (!proc) return;

    std::unordered_set<ino_t> seen_inodes;
    std::vector<int> namespace_fds;

    struct dirent *entry;
    while ((entry = readdir(proc))) {
        if (entry->d_type != DT_DIR) continue;

        std::string pid = entry->d_name;
        if (pid.find_first_not_of("0123456789") != std::string::npos) continue;

        std::string ns_path = "/proc/" + pid + "/ns/mnt";
        int fd = open(ns_path.c_str(), O_RDONLY);
        if (fd < 0) continue;

        struct stat st = {};
        if (fstat(fd, &st) == 0) {
            if (seen_inodes.find(st.st_ino) == seen_inodes.end()) {
                seen_inodes.insert(st.st_ino);
                namespace_fds.push_back(fd);
            } else {
                close(fd);
            }
        } else {
            close(fd);
        }
    }

    closedir(proc);

    int orig_ns = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
    if (orig_ns < 0) {
        return;
    }

    for (int their_ns : namespace_fds) {
        if (setns(their_ns, CLONE_NEWNS) != 0) {
            close(their_ns);
            continue;
        }

        std::vector<ToUmount> umounts = umount_list(UmountsNoPrivate);

        for (auto it = umounts.rbegin(); it != umounts.rend(); ++it) {
            int mnt_fd;
            std::string mnt_fd_path;

            if (!umount_get_fd(*it, mnt_fd, mnt_fd_path)) continue;

            if (mount(nullptr, mnt_fd_path.c_str(), nullptr, MS_PRIVATE | MS_REC, nullptr) == -1) {
                PLOGE("mount_ns_private: mount(%s, MS_PRIVATE | MS_REC)", it->mountPoint.c_str());
            }

            close(mnt_fd);
        }

        close(their_ns);
    }

    setns(orig_ns, CLONE_NEWNS);
    close(orig_ns);
}

extern "C" void mount_ns_main(char **argv) {
    if (access(TMP_PATH "/clean_zygote", F_OK) != 0) {
        return;
    }

    pid_t m64 = -1;
    if (LP_SELECT(false, true)) {
        m64 = mount_spawn_ns(argv, "zygisk-m64", TMP_PATH "/mns64");
    }

    pid_t m32 = mount_spawn_ns(argv, "zygisk-m32", TMP_PATH "/mns32");

    if (access(TMP_PATH "/private_mounts", F_OK) != 0) {
        return;
    }

    mount("/system", "/system", nullptr, MS_BIND | MS_REC, nullptr);
    mount(nullptr, "/system", nullptr, MS_PRIVATE | MS_REC, nullptr);
    mount(nullptr, "/system_ext", nullptr, MS_PRIVATE | MS_REC, nullptr);
    mount(nullptr, "/product", nullptr, MS_PRIVATE | MS_REC, nullptr);
    mount(nullptr, "/vendor", nullptr, MS_PRIVATE | MS_REC, nullptr);

    int orig_ns = -1;
    if (m64 > 0) {
        if (switch_mnt_ns(m64, &orig_ns)) {
            mount(nullptr, "/system", nullptr, MS_PRIVATE | MS_REC, nullptr);
            umount2("/system", MNT_DETACH);
            switch_mnt_ns(0, &orig_ns);
        }
    }

    if (switch_mnt_ns(m32, &orig_ns)) {
        mount(nullptr, "/system", nullptr, MS_PRIVATE | MS_REC, nullptr);
        umount2("/system", MNT_DETACH);
        switch_mnt_ns(0, &orig_ns);
    }
}
