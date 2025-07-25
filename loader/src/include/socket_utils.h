#ifndef SOCKET_UTILS_H
#define SOCKET_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

ssize_t read_n(int fd, void *buf, size_t n);

ssize_t write_n(int fd, const void *buf, size_t n);

int read_fd(int fd);

ssize_t write_string(int fd, const char *str);

char *read_string(int fd);

#define write_func_def(type)              \
  ssize_t write_## type(int fd, type val)

#define read_func_def(type)               \
  ssize_t read_## type(int fd, type *val)

write_func_def(uint8_t);

read_func_def(uint8_t);

write_func_def(uint32_t);

read_func_def(uint32_t);

write_func_def(size_t);

read_func_def(size_t);

#ifdef __cplusplus
}
#endif

#endif /* SOCKET_UTILS_H */