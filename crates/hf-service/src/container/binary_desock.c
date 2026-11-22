/*
 * oxfuzz network shim for binary-only fuzzing.
 *
 * Loaded into a server program with LD_PRELOAD, it lets a fuzzer deliver one
 * input to the server with no network:
 *
 *   Stream servers (socket, bind, listen, accept)
 *     bind    does nothing, so no port is needed.
 *     listen  replaces the listening descriptor with one that is always
 *             ready, so select, poll, and epoll return at once.
 *     accept  the first call returns one end of a socket pair; a helper
 *             thread writes the input into the other end, signals end of
 *             stream, and discards whatever the server sends. A later call
 *             ends the process: one input is one connection.
 *
 *   Datagram servers (socket, bind, recvfrom)
 *     bind    replaces the socket with one end of a datagram socket pair;
 *             the helper thread sends the input into the other end. When
 *             the input is used up and the server asks for another
 *             datagram, the process ends.
 *
 * With OXFUZZ_DESOCK_MESSAGES set, the input is a sequence of messages
 * separated by the four bytes FF FE FD FC. Each message is sent only after
 * the server has read all of the one before, so a server that reads one
 * request per call sees one message per call. Without it, a stream server
 * gets the whole input as one byte stream and a datagram server gets it as
 * one datagram.
 *
 * Nothing here opens a network connection.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#ifndef SIOCOUTQ
#define SIOCOUTQ 0x5411
#endif

#define MAX_INPUT (4u * 1024 * 1024)
#define MAX_DATAGRAM 65507u
#define SEPARATOR "\xff\xfe\xfd\xfc"
#define SEPARATOR_BYTES 4u
/* Used only if the kernel cannot say how much the server has left unread. */
#define FALLBACK_PACE_MS 20

static int listen_fd = -1;
static int conn_fd = -1;
static int dgram_fd = -1;
static int peer_fd = -1;
static int served;
static int datagram;
/* Every datagram was delivered and read: the next receive ends the process. */
static volatile int input_used_up;

static unsigned char *input;
static size_t input_len;

static void read_input(void) {
  size_t room = 65536;
  input = malloc(room);
  while (input != NULL && input_len < MAX_INPUT) {
    ssize_t n;
    if (input_len == room) {
      unsigned char *grown = realloc(input, room * 2);
      if (grown == NULL) break;
      input = grown;
      room *= 2;
    }
    n = read(0, input + input_len, room - input_len);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) break;
    input_len += (size_t)n;
  }
  if (input == NULL) input_len = 0;
}

/* Discard what the server has sent; it is not part of the test. Returns 0
   when the server closed a stream connection. */
static int drain(int wait_ms) {
  char out[4096];
  struct pollfd p = {peer_fd, POLLIN, 0};
  if (poll(&p, 1, wait_ms) <= 0) return 1;
  if (p.revents & POLLIN) {
    ssize_t n = recv(peer_fd, out, sizeof out, MSG_DONTWAIT);
    if (n == 0 && !datagram) return 0;
    return 1;
  }
  return (p.revents & (POLLHUP | POLLERR)) ? 0 : 1;
}

/* Wait until the server has read everything sent so far. The server is
   usually already waiting, so look again at once a few hundred times before
   sleeping between looks. */
static int wait_until_read(void) {
  for (unsigned looks = 0;; looks++) {
    int unread = 0;
    if (ioctl(peer_fd, SIOCOUTQ, &unread) != 0) return drain(FALLBACK_PACE_MS);
    if (unread == 0) return 1;
    if (looks < 256) {
      sched_yield();
      if ((looks & 15) == 15 && !drain(0)) return 0;
    } else if (!drain(1)) {
      return 0;
    }
  }
}

static int deliver(const unsigned char *bytes, size_t len) {
  size_t sent = 0;
  if (datagram) {
    /* MSG_NOSIGNAL: a server that went away must not kill the process with
       SIGPIPE, which would look like a crash. */
    return send(peer_fd, bytes, len > MAX_DATAGRAM ? MAX_DATAGRAM : len, MSG_NOSIGNAL) >= 0;
  }
  while (sent < len) {
    struct pollfd p = {peer_fd, POLLIN | POLLOUT, 0};
    if (poll(&p, 1, -1) < 0) {
      if (errno == EINTR) continue;
      return 0;
    }
    if (p.revents & POLLIN) {
      char out[4096];
      ssize_t n = recv(peer_fd, out, sizeof out, MSG_DONTWAIT);
      if (n == 0) return 0;
    } else if (p.revents & (POLLHUP | POLLERR)) {
      return 0;
    }
    if (p.revents & POLLOUT) {
      ssize_t n = send(peer_fd, bytes + sent, len - sent, MSG_NOSIGNAL | MSG_DONTWAIT);
      if (n < 0) {
        if (errno == EINTR || errno == EAGAIN) continue;
        return 0;
      }
      sent += (size_t)n;
    }
  }
  return 1;
}

static size_t message_end(size_t from) {
  for (size_t at = from; at + SEPARATOR_BYTES <= input_len; at++) {
    if (memcmp(input + at, SEPARATOR, SEPARATOR_BYTES) == 0) return at;
  }
  return input_len;
}

static void *shuttle(void *unused) {
  int messages = getenv("OXFUZZ_DESOCK_MESSAGES") != NULL;
  int open = 1;
  size_t at = 0;
  (void)unused;
  read_input();
  while (open && at < input_len) {
    size_t end = messages ? message_end(at) : input_len;
    if (end > at) {
      open = deliver(input + at, end - at);
      if (open && (messages || datagram)) open = wait_until_read();
    }
    at = end < input_len ? end + SEPARATOR_BYTES : end;
  }
  if (datagram) {
    /* A datagram socket has no end of stream. Mark the input used up and
       wake a server that is waiting in a receive or a readiness call; its
       next receive ends the process. */
    input_used_up = 1;
    shutdown(dgram_fd, SHUT_RD);
    for (;;) drain(-1);
  }
  if (open) shutdown(peer_fd, SHUT_WR);
  while (open) open = drain(-1);
  return NULL;
}

static int start_shuttle(void) {
  pthread_t thread;
  if (pthread_create(&thread, NULL, shuttle, NULL) != 0) return -1;
  pthread_detach(thread);
  return 0;
}

static void loopback(struct sockaddr *addr, socklen_t *len) {
  struct sockaddr_in local;
  if (!addr || !len) return;
  memset(&local, 0, sizeof local);
  local.sin_family = AF_INET;
  local.sin_port = htons(40000);
  local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  memcpy(addr, &local, *len < sizeof local ? *len : sizeof local);
  *len = sizeof local;
}

/* Put one end of a datagram socket pair where the server's socket was. */
static int become_datagram_peer(int fd) {
  int pair[2];
  int status = fcntl(fd, F_GETFL);
  int descriptor = fcntl(fd, F_GETFD);
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) != 0) return -1;
  if (dup2(pair[0], fd) < 0) {
    close(pair[0]);
    close(pair[1]);
    return -1;
  }
  close(pair[0]);
  if (status >= 0 && (status & O_NONBLOCK)) fcntl(fd, F_SETFL, O_NONBLOCK);
  if (descriptor >= 0 && (descriptor & FD_CLOEXEC)) fcntl(fd, F_SETFD, FD_CLOEXEC);
  dgram_fd = fd;
  peer_fd = pair[1];
  datagram = 1;
  served = 1;
  return start_shuttle();
}

int bind(int fd, const struct sockaddr *addr, socklen_t len) {
  int type = 0;
  socklen_t size = sizeof type;
  (void)len;
  if (!served && addr != NULL && (addr->sa_family == AF_INET || addr->sa_family == AF_INET6) &&
      getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size) == 0 && type == SOCK_DGRAM) {
    return become_datagram_peer(fd);
  }
  return 0;
}

int listen(int fd, int backlog) {
  int ready = eventfd(1, 0);
  (void)backlog;
  if (ready < 0) return -1;
  if (dup2(ready, fd) < 0) {
    close(ready);
    return -1;
  }
  close(ready);
  listen_fd = fd;
  return 0;
}

int accept4(int fd, struct sockaddr *addr, socklen_t *len, int flags) {
  int pair[2];
  (void)fd;
  if (served) _exit(0);
  served = 1;
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) return -1;
  conn_fd = pair[0];
  peer_fd = pair[1];
  if (flags & SOCK_NONBLOCK) fcntl(conn_fd, F_SETFL, O_NONBLOCK);
  if (flags & SOCK_CLOEXEC) fcntl(conn_fd, F_SETFD, FD_CLOEXEC);
  if (start_shuttle() != 0) return -1;
  loopback(addr, len);
  return conn_fd;
}

int accept(int fd, struct sockaddr *addr, socklen_t *len) {
  return accept4(fd, addr, len, 0);
}

static int ours(int fd) {
  return fd >= 0 && (fd == listen_fd || fd == conn_fd || fd == dgram_fd);
}

static int is_datagram(int fd) { return fd >= 0 && fd == dgram_fd; }

/* The server asked the datagram socket for more and there is none left. */
static ssize_t received(int fd, ssize_t got) {
  if (is_datagram(fd) && got <= 0 && input_used_up) _exit(0);
  return got;
}

ssize_t recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *addr,
                 socklen_t *addr_len) {
  static ssize_t (*real)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
  ssize_t got;
  if (!real) real = dlsym(RTLD_NEXT, "recvfrom");
  if (!is_datagram(fd)) return real(fd, buf, len, flags, addr, addr_len);
  got = received(fd, real(fd, buf, len, flags, NULL, NULL));
  if (got >= 0) loopback(addr, addr_len);
  return got;
}

ssize_t __recvfrom_chk(int fd, void *buf, size_t len, size_t room, int flags,
                       struct sockaddr *addr, socklen_t *addr_len) {
  if (len > room) abort();
  return recvfrom(fd, buf, len, flags, addr, addr_len);
}

ssize_t recv(int fd, void *buf, size_t len, int flags) {
  static ssize_t (*real)(int, void *, size_t, int);
  if (!real) real = dlsym(RTLD_NEXT, "recv");
  return received(fd, real(fd, buf, len, flags));
}

ssize_t __recv_chk(int fd, void *buf, size_t len, size_t room, int flags) {
  if (len > room) abort();
  return recv(fd, buf, len, flags);
}

ssize_t read(int fd, void *buf, size_t len) {
  static ssize_t (*real)(int, void *, size_t);
  if (!real) real = dlsym(RTLD_NEXT, "read");
  return received(fd, real(fd, buf, len));
}

ssize_t __read_chk(int fd, void *buf, size_t len, size_t room) {
  if (len > room) abort();
  return read(fd, buf, len);
}

ssize_t recvmsg(int fd, struct msghdr *message, int flags) {
  static ssize_t (*real)(int, struct msghdr *, int);
  ssize_t got;
  if (!real) real = dlsym(RTLD_NEXT, "recvmsg");
  if (!is_datagram(fd)) return real(fd, message, flags);
  got = received(fd, real(fd, message, flags));
  if (got >= 0 && message != NULL && message->msg_name != NULL) {
    loopback(message->msg_name, &message->msg_namelen);
  }
  return got;
}

/* A reply to a datagram has nowhere to go and is not part of the test. */
ssize_t sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *addr,
               socklen_t addr_len) {
  static ssize_t (*real)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
  if (is_datagram(fd)) return (ssize_t)len;
  if (!real) real = dlsym(RTLD_NEXT, "sendto");
  return real(fd, buf, len, flags, addr, addr_len);
}

ssize_t sendmsg(int fd, const struct msghdr *message, int flags) {
  static ssize_t (*real)(int, const struct msghdr *, int);
  if (is_datagram(fd)) {
    size_t total = 0;
    for (size_t part = 0; message != NULL && part < message->msg_iovlen; part++) {
      total += message->msg_iov[part].iov_len;
    }
    return (ssize_t)total;
  }
  if (!real) real = dlsym(RTLD_NEXT, "sendmsg");
  return real(fd, message, flags);
}

int connect(int fd, const struct sockaddr *addr, socklen_t len) {
  static int (*real)(int, const struct sockaddr *, socklen_t);
  /* A datagram server may name its one peer; the stand-in already has it. */
  if (is_datagram(fd)) return 0;
  if (!real) real = dlsym(RTLD_NEXT, "connect");
  return real(fd, addr, len);
}

int setsockopt(int fd, int level, int name, const void *value, socklen_t len) {
  static int (*real)(int, int, int, const void *, socklen_t);
  /* TCP and UDP options do not apply to the stand-in descriptors. */
  if (ours(fd)) return 0;
  if (!real) real = dlsym(RTLD_NEXT, "setsockopt");
  return real(fd, level, name, value, len);
}

int getsockname(int fd, struct sockaddr *addr, socklen_t *len) {
  static int (*real)(int, struct sockaddr *, socklen_t *);
  if (ours(fd)) {
    loopback(addr, len);
    return 0;
  }
  if (!real) real = dlsym(RTLD_NEXT, "getsockname");
  return real(fd, addr, len);
}

int getpeername(int fd, struct sockaddr *addr, socklen_t *len) {
  static int (*real)(int, struct sockaddr *, socklen_t *);
  if (fd >= 0 && (fd == conn_fd || fd == dgram_fd)) {
    loopback(addr, len);
    return 0;
  }
  if (!real) real = dlsym(RTLD_NEXT, "getpeername");
  return real(fd, addr, len);
}
