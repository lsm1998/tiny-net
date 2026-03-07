#ifndef TINY_NET_NET_API_H
#define TINY_NET_NET_API_H

#include "types.h"
#include "socket.h"
#include "tool.h"

#undef htons
#define htons x_htons

#undef ntohs
#define ntohs x_ntohs

#undef htonl
#define htonl x_htonl

#undef ntohl
#define ntohl x_ntohl

char* x_inet_ntoa(struct in_addr in);

uint32_t x_inet_addr(const char* cp);

int x_inet_pton(int family, const char* src, void* dst);

const char* x_inet_ntop(int family, const void* src, char* dst, size_t size);

#define inet_ntoa(in) x_inet_ntoa(in)

#define inet_addr(cp) x_inet_addr(cp)

#define inet_pton(family, src, dst) x_inet_pton(family, src, dst)

#define inet_ntop(family, src, dst, size) x_inet_ntop(family, src, dst, size)

#define socketaddr_in  x_socketaddr_in

#undef sockaddr
#define sockaddr            x_sockaddr

#define sockaddr_in      x_sockaddr_in

#undef socklen_t
#define socklen_t x_socklen_t

#define socket(domain, type, protocol) x_socket(domain, type, protocol)

#define bind(fd, addr, addrlen) x_bind(fd, addr, addrlen)

#define listen(fd, backlog) x_listen(fd, backlog)

#define accept(fd, addr, addrlen) x_accept(fd, addr, addrlen)

#define connect(fd, addr, addrlen) x_connect(fd, addr, addrlen)

#define send(fd, buf, len, flags) x_send(fd, buf, len, flags)

#define recv(fd, buf, len, flags) x_recv(fd, buf, len, flags)

#define read(fd, buf, len) x_read(fd, buf, len)

#define write(fd, buf, len) x_write(fd, buf, len)

#define close(fd) x_close(fd)

#define setsockopt(fd, level, opt_name, opt_val, opt_len) x_setsockopt(fd, level, opt_name, opt_val, opt_len)

#define sendto(fd, buf, len, flags, addr, addrlen) x_sendto(fd, buf, len, flags, addr, addrlen)

#define recvfrom(fd, buf, len, flags, addr, addrlen) x_recvfrom(fd, buf, len, flags, addr, addrlen)

#define getaddrinfo(hostname, service, hints, res) x_getaddrinfo(hostname, service, hints, res)

#define freeaddrinfo(res) x_freeaddrinfo(res)

#define select(n_fds, read_fds, write_fds, except_fds, timeout) x_select(n_fds, read_fds, write_fds, except_fds, timeout)

#endif //TINY_NET_NET_API_H
