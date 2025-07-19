#ifndef REZYGISK_RULES_HPP
#define REZYGISK_RULES_HPP

#include <string>

bool rules_reload();
void rules_unload();

bool rules_should_deny(uid_t uid, const std::string &process, const std::string &data_dir,
                       bool on_denylist);

bool rules_should_umount(std::string &mountpoint);

#endif //REZYGISK_RULES_HPP
