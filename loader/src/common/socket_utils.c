#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>

#include <unistd.h>
#include <poll.h>

#include "logging.h"

#include "socket_utils.h"


ssize_t read_n(int fd, void *buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t r = TEMP_FAILURE_RETRY(read(fd, (char*)buf + total, n - total));
        if (r == -1 && (errno == EAGAIN || errno == EWOULDBLOCK) && total > 0) {
            struct pollfd pfd = { .fd = fd, .events = POLLIN };
            TEMP_FAILURE_RETRY(poll(&pfd, 1, -1));
            continue;
        }
        if (r <= 0) return r;
        total += r;
    }
    return (ssize_t) total;
}


ssize_t write_n(int fd, const void *buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t w = TEMP_FAILURE_RETRY(write(fd, (char*)buf + total, n - total));
        if (w == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            TEMP_FAILURE_RETRY(poll(&pfd, 1, -1));
            continue;
        }
        if (w <= 0) return w;
        total += w;
    }
    return (ssize_t) total;
}

/* TODO: Standardize how to log errors */
int read_fd(int fd) {
  char cmsgbuf[CMSG_SPACE(sizeof(int))];

  int cnt = 1;
  struct iovec iov = {
    .iov_base = &cnt,
    .iov_len = sizeof(cnt)
  };

  struct msghdr msg = {
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = cmsgbuf,
    .msg_controllen = sizeof(cmsgbuf)
  };

  ssize_t ret = TEMP_FAILURE_RETRY(recvmsg(fd, &msg, MSG_WAITALL));
  if (ret == -1) {
    PLOGE("recvmsg");

    return -1;
  }

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  if (cmsg == NULL) {
    PLOGE("CMSG_FIRSTHDR");

    return -1;
  }

  int sendfd;
  memcpy(&sendfd, CMSG_DATA(cmsg), sizeof(int));

  return sendfd;
}

ssize_t write_string(int fd, const char *str) {
  size_t str_len = strlen(str);
  ssize_t write_bytes = TEMP_FAILURE_RETRY(write_n(fd, &str_len, sizeof(size_t)));
  if (write_bytes != (ssize_t)sizeof(size_t)) {
    LOGE("Failed to write string length: Not all bytes were written (%zd != %zu).\n", write_bytes, sizeof(size_t));

    return -1;
  }

  write_bytes = TEMP_FAILURE_RETRY(write_n(fd, str, str_len));
  if (write_bytes != (ssize_t)str_len) {
    LOGE("Failed to write string: Promised bytes doesn't exist (%zd != %zu).\n", write_bytes, str_len);

    return -1;
  }

  return write_bytes;
}

char *read_string(int fd) {
  size_t str_len = 0;
  ssize_t read_bytes = TEMP_FAILURE_RETRY(read_n(fd, &str_len, sizeof(size_t)));
  if (read_bytes != (ssize_t)sizeof(size_t)) {
    LOGE("Failed to read string length: Not all bytes were read (%zd != %zu).\n", read_bytes, sizeof(size_t));

    return NULL;
  }

  char *buf = malloc(str_len + 1);
  if (buf == NULL) {
    PLOGE("allocate memory for string");

    return NULL;
  }

  read_bytes = TEMP_FAILURE_RETRY(read_n(fd, buf, str_len));
  if (read_bytes != (ssize_t)str_len) {
    LOGE("Failed to read string: Promised bytes doesn't exist (%zd != %zu).\n", read_bytes, str_len);

    free(buf);

    return NULL;
  }

  if (str_len > 0) buf[str_len] = '\0';

  return buf;
}

#define write_func(type)                                      \
  ssize_t write_## type(int fd, type val) {                   \
    return TEMP_FAILURE_RETRY(write_n(fd, &val, sizeof(type))); \
  }

#define read_func(type)                                     \
  ssize_t read_## type(int fd, type *val) {                 \
    return TEMP_FAILURE_RETRY(read_n(fd, val, sizeof(type))); \
  }

write_func(uint8_t)
read_func(uint8_t)

write_func(uint32_t)
read_func(uint32_t)

write_func(size_t)
read_func(size_t)
