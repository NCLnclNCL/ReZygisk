#include <vector>
#include <string>
#include <fstream>
#include <sstream>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <sys/mount.h>


#include "logging.h"
#include "umount.hpp"
#include "rules.hpp"

char modules_dev[64] = {0};

static std::string path_dev_str(const char *path) {
    struct stat st = {};

    if (stat(path, &st) != 0) {
        PLOGE("path_dev_str: stat(%s)", path);
        return "?";
    }

    std::ostringstream oss;
    oss << major(st.st_dev) << ":" << minor(st.st_dev);
    return oss.str();
}

static std::string fd_dev_str(int fd) {
    struct stat st = {};

    if (fstat(fd, &st) != 0) {
        PLOGE("fd_dev_str: fstat(%d)", fd);
        return "?";
    }

    std::ostringstream oss;
    oss << major(st.st_dev) << ":" << minor(st.st_dev);
    return oss.str();
}

void umount_init_modules_dev() {
    if (modules_dev[0]) return;

    std::string root_dev = path_dev_str("/");
    std::string data_dev = path_dev_str("/data");
    std::string mod_dev = path_dev_str("/data/adb/modules");

    if (mod_dev != root_dev && mod_dev != data_dev && mod_dev != "?") {
        strcpy(modules_dev, mod_dev.c_str());
    } else {
        strcpy(modules_dev, "- no separate device -");
    }
}

static int mount_id_for_fd(int fd) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);

    std::ifstream info(path);
    if (!info) {
        PLOGE("mount_id_for_fd: open %s", path);
        return -1;
    }

    std::string line;
    while (std::getline(info, line)) {
        constexpr char prefix[] = "mnt_id:";
        if (line.compare(0, sizeof(prefix) - 1, prefix) == 0) {
            std::istringstream iss(line.substr(sizeof(prefix) - 1));
            int mnt_id;
            iss >> mnt_id;
            if (!iss.fail()) return mnt_id;
            break;
        }
    }
    LOGE("mount_id_for_fd: mnt_id not found");
    return -1;
}

std::vector<ToUmount> umount_list(umount_filter filter) {
    umount_init_modules_dev();

    std::vector<ToUmount> umounts;

    std::ifstream mountinfo("/proc/self/mountinfo");
    if (!mountinfo) {
        PLOGE("umount_list: open /proc/self/mountinfo");
        return umounts;
    }

    std::string line;
    while (std::getline(mountinfo, line)) {
        size_t sep = line.find(" - ");
        if (sep == std::string::npos) continue;

        std::string pre = line.substr(0, sep);
        std::string post = line.substr(sep + 3);

        if (filter == UmountsNoPrivate && pre.find("shared:") == std::string::npos &&
            pre.find("master:") == std::string::npos &&
            pre.find("propagate_from:") == std::string::npos) {
            continue;
        }

        std::istringstream preIss(pre);
        std::string mountId, parentId, majorMinor, root, mountPoint;

        if (!(preIss >> mountId >> parentId >> majorMinor >> root >> mountPoint)) {
            LOGE("umount_list: failed to parse mountinfo line part '%s'", pre.c_str());
            continue;
        }

        std::istringstream postIss(post);
        std::string fsType, mountSource, fsOptions;

        if (!(postIss >> fsType >> mountSource)) {
            LOGE("umount_list: failed to parse mountinfo line part '%s'", post.c_str());
            continue;
        }

        if (mountSource == "KSU"
            || mountSource == "APatch"
            || mountSource == "magisk"
            || root.find("/adb/") != std::string::npos
            || majorMinor == modules_dev
            || rules_should_umount(mountPoint)) {
            struct ToUmount um = {
                    .mountPoint = mountPoint,
                    .mountId = (int) strtol(mountId.c_str(), nullptr, 10),
                    .majorMinor = majorMinor
            };
            umounts.push_back(um);
        }
    }

    return umounts;
}

bool umount_get_fd(ToUmount &u, int &mnt_fd, std::string &fd_path) {
    /* INFO: These checks are to avoid issues with TOCTTOU and nested mounts */
    mnt_fd = open(u.mountPoint.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (mnt_fd == -1) {
        PLOGE("umount_get_fd: mnt_fd = open(%s)", u.mountPoint.c_str());
        return false;
    }

    int mnt_fd_id = mount_id_for_fd(mnt_fd);
    if (mnt_fd_id != u.mountId && mnt_fd_id != -1) {
        LOGE("umount_get_fd: mount id expected %d vs actual %d for %s", u.mountId, mnt_fd_id, u.mountPoint.c_str());
        close(mnt_fd);
        return false;
    }

    char mnt_fd_path[64];
    snprintf(mnt_fd_path, sizeof(mnt_fd_path), "/proc/self/fd/%d", mnt_fd);

    std::string mnt_fd_dev = fd_dev_str(mnt_fd);
    if (mnt_fd_dev != u.majorMinor && mnt_fd_dev != "?") {
        LOGE("umount_get_fd: dev expected %s vs actual %s for %s", u.majorMinor.c_str(), mnt_fd_dev.c_str(), u.mountPoint.c_str());
        close(mnt_fd);
        return false;
    }

    fd_path = std::string(mnt_fd_path);
    return true;
}
