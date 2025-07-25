#ifndef REZYGISK_UMOUNT_HPP
#define REZYGISK_UMOUNT_HPP

#include <string>
#include <vector>
#include <sys/socket.h>
#include <linux/un.h>
#include "daemon.h"

static struct sockaddr_un umountd_sock_addr = {
        .sun_family = AF_UNIX,
        .sun_path = TMP_PATH "/tmp/umountd.sock\0"
};

struct ToUmount {
    std::string mountPoint;
    int mountId;
    std::string majorMinor;
    bool get_fd(int &mnt_fd, std::string &fd_path) const;
};

enum umount_filter {
    UmountsGetAll,
    UmountsNoPrivate
};

std::vector<ToUmount> umount_list(umount_filter filter);

#endif //REZYGISK_UMOUNT_HPP
