#include <sstream>
#include <fstream>
#include <vector>
#include <unordered_set>

#include <sys/types.h>
#include <sys/stat.h>

#include "rules.hpp"
#include "logging.h"
#include "daemon.h"

struct AppRule {
    uid_t uid_from{0};
    uid_t uid_to{0};
    std::string name;
    bool is_prefix{false};
    bool deny{true};
};

static timespec last_mtime = {};

static const char *rules_txt = TMP_PATH "/rules.txt";

static std::unordered_set<std::string> *never_umount = nullptr;
static std::unordered_set<std::string> *umount_rules = nullptr;
static std::vector<std::string> *umount_prefix_rules = nullptr;
static std::vector<AppRule> *app_rules = nullptr;

static inline std::string_view trim(std::string_view sv) {
    auto first = sv.find_first_not_of(" \t\n\r\f\v");
    if (first == std::string_view::npos) return {};
    auto last = sv.find_last_not_of(" \t\n\r\f\v");
    return sv.substr(first, last - first + 1);
}

static bool is_digits(std::string_view sv) {
    return !sv.empty() && std::all_of(sv.begin(), sv.end(), [](char c) { return std::isdigit(c); });
}

std::string basename(std::string_view path) {
    std::size_t end = path.size();
    while (end > 0 && path[end - 1] == '/') --end;

    if (end == 0) return {};

    std::size_t slash = path.rfind('/', end - 1);
    if (slash == std::string_view::npos) {
        return std::string{path.substr(0, end)};
    }

    return std::string{path.substr(slash + 1, end - slash - 1)};
}

static AppRule parse_app_rule(std::string s) {
    AppRule rule;

    if (s == "*") {
        rule.uid_from = 0;
        rule.uid_to = std::numeric_limits<uid_t>::max();
        return rule;
    }

    if (s.starts_with('-')) {
        rule.deny = false;
        s = trim(s.substr(1));
    }

    if (is_digits(s)) {
        rule.uid_from = rule.uid_to = std::strtoul(s.c_str(), nullptr, 10);
        return rule;
    }

    auto comma = s.find('-');
    if (comma != std::string_view::npos) {
        std::string left = std::string{trim(s.substr(0, comma))};
        std::string right = std::string{trim(s.substr(comma + 1))};
        if (is_digits(left) && is_digits(right)) {
            rule.uid_from = std::strtoul(left.c_str(), nullptr, 10);
            rule.uid_to = std::strtoul(right.c_str(), nullptr, 10);
            return rule;
        } else if (is_digits(left) && right == "*") {
            rule.uid_from = std::strtoul(left.c_str(), nullptr, 10);
            rule.uid_to = std::numeric_limits<uid_t>::max();
        }

        LOGE("parse_app_rule: Bad rule %s", s.c_str());
        return rule;
    }

    if (s.ends_with('*')) {
        rule.is_prefix = true;
        s = s.substr(0, s.size() - 1);
    }

    rule.name = std::move(s);
    return rule;
}

bool rules_reload() {
    struct stat st = {};
    if (stat(rules_txt, &st) != 0) return false;
    if (st.st_mtim.tv_sec == last_mtime.tv_sec && st.st_mtim.tv_nsec == last_mtime.tv_nsec) {
        return false;
    }
    last_mtime = st.st_mtim;

    if (umount_rules) umount_rules->clear();
    else umount_rules = new std::unordered_set<std::string>();

    if (umount_prefix_rules) umount_prefix_rules->clear();
    else umount_prefix_rules = new std::vector<std::string>();

    if (app_rules) app_rules->clear();
    else app_rules = new std::vector<AppRule>();

    if (!never_umount) {
        never_umount = new std::unordered_set<std::string>();
        never_umount->insert("/");
        never_umount->insert("/proc");
        never_umount->insert("/sys");
        never_umount->insert("/dev");
        never_umount->insert("/data");
        never_umount->insert("/system_ext");
        never_umount->insert("/product");
        never_umount->insert("/vendor");
        never_umount->insert("/mnt");
    }

    std::ifstream txt(rules_txt);
    if (!txt) return false;

    std::string line;
    while (std::getline(txt, line)) {
        line = trim(line);
        if (line.empty() || line.starts_with('#')) continue;

        if (line.starts_with('/')) {
            if (line.ends_with('*')) {
                umount_prefix_rules->push_back(line.substr(0, line.size() - 1));
            } else if (!never_umount->contains(line)) {
                umount_rules->insert(line);
            }
            continue;
        }

        app_rules->push_back(parse_app_rule(std::move(line)));
    }

    return true;
}

void rules_unload() {
    last_mtime = {};
    delete never_umount;
    never_umount = nullptr;
    delete umount_rules;
    umount_rules = nullptr;
    delete umount_prefix_rules;
    umount_prefix_rules = nullptr;
    delete app_rules;
    app_rules = nullptr;
}

bool rules_should_deny(uid_t uid, const std::string &process, const std::string &data_dir,
                       bool on_denylist) {
    if (!app_rules) return on_denylist;
    if (uid == 0) return false;

    std::string app = basename(data_dir);

    for (AppRule &rule: *app_rules) {
        if (rule.uid_from || rule.uid_to) {
            if (uid >= rule.uid_from && uid <= rule.uid_to) {
                return rule.deny;
            }
        }

        if (!rule.name.empty()) {
            if (rule.is_prefix) {
                if (!process.starts_with(rule.name) && !app.starts_with(rule.name)) continue;
            } else {
                if (process != rule.name && app != rule.name) continue;
            }
            return rule.deny;
        }
    }

    return on_denylist;
}

bool rules_should_umount(std::string &mountpoint) {
    if (!umount_rules || !umount_prefix_rules) return false;
    if (umount_rules->contains(mountpoint)) return true;
    for (std::string &prefix: *umount_prefix_rules) {
        if (mountpoint.starts_with(prefix)) {
            return !never_umount->contains(mountpoint);
        }
    }
    return false;
}
