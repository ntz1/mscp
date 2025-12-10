/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef _PLATFORM_H_
#define _PLATFORM_H_

#include <config.h>

#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>

#if defined(_WIN32)
// Include winsock headers for network byte order functions on MinGW/Windows.
#include <winsock2.h> 
#include <ws2tcpip.h>
// Prototypes for missing POSIX functions (implemented in platform.c)
// char *strndup(const char *s, size_t n);
char *getpass(const char *prompt);

struct iovec
{
    void    *iov_base;  /* Base address of a memory region for input or output */
    size_t   iov_len;   /* The size of the memory pointed to by iov_base */
};
ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
#endif

int nr_cpus(void);
int set_thread_affinity(pthread_t tid, int core);
int setutimes(const char *path, struct timespec atime, struct timespec mtime);

/*
 * macOS does not support sem_init(). macOS (seems to) releases the
 * named semaphore when associated mscp process finished. In linux,
 * program (seems to) need to release named semaphore in /dev/shm by
 * sem_unlink() explicitly. So, using sem_init() (unnamed semaphore)
 * in linux and using sem_open() (named semaphore) in macOS without
 * sem_unlink() are reasonable (?).
 */
sem_t *sem_create(int value);
int sem_release(sem_t *sem);

#ifdef HAVE_HTONLL
#include <arpa/inet.h> /* Apple has htonll and ntohll in arpa/inet.h */
#endif

/* copied from libssh: libssh/include/libssh/priv.h */
#ifndef HAVE_HTONLL
#ifdef WORDS_BIGENDIAN
#define htonll(x) (x)
#else
#define htonll(x) (((uint64_t)htonl((x)&0xFFFFFFFF) << 32) | htonl((x) >> 32))
#endif
#endif

#ifndef HAVE_NTOHLL
#ifdef WORDS_BIGENDIAN
#define ntohll(x) (x)
#else
#define ntohll(x) (((uint64_t)ntohl((x)&0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif
#endif

#endif /* _PLATFORM_H_ */
