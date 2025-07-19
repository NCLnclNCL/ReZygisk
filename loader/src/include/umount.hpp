#ifndef REZYGISK_UMOUNT_HPP
#define REZYGISK_UMOUNT_HPP

#include <string>
#include <vector>

extern char modules_dev[64];

struct ToUmount {
    std::string mountPoint;
    int mountId;
    std::string majorMinor;
};

enum umount_filter {
    UmountsGetAll,
    UmountsNoPrivate
};

std::vector<ToUmount> umount_list(umount_filter filter);
bool umount_get_fd(ToUmount &u, int &mnt_fd, std::string &fd_path);
void umount_init_modules_dev();

#endif //REZYGISK_UMOUNT_HPP
