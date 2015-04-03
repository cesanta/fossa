#include "avrsupport.h"
/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */
#include <Arduino.h>

void blink(int times, int ms) {
  static int inited = 0;
  int i;

  if (!inited) {
    DDRB = 0b11111111;
    inited = 1;
  }

  for (i = 0; i < times; i++) {
    PORTB = 0xFF;
    delay(ms);
    PORTB = 0x00;
    if (i != times - 1) {
      delay(ms);
    }
  }
}

extern unsigned int __heap_start;
extern void* __brkval;

struct __freelist {
  size_t sz;
  struct __freelist* nx;
};

extern struct __freelist* __flp;

int get_freelistsize() {
  struct __freelist* current;
  int total = 0;
  for (current = __flp; current; current = current->nx) {
    total += 2;
    total += (int) current->sz;
  }
  return total;
}

int get_freememsize() {
  int free_memory;
  if ((int) __brkval == 0) {
    free_memory = ((int) &free_memory) - ((int) &__heap_start);
  } else {
    free_memory = ((int) &free_memory) - ((int) __brkval);
    free_memory += get_freelistsize();
  }
  return free_memory;
}

/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include <Arduino.h>
#include <stdio.h>

long long int to64(const char* str) {
  long long int res = 0;
  char negative = 0;

  while (isspace(*str)) str++;

  if (*str == '+') {
    str++;
  } else if (*str == '-') {
    negative = 1;
    str++;
  }

  while (*str >= '0' && *str <= '9') {
    res = res * 10 + (*str - '0');
    str++;
  }

  return negative ? -res : res;
}

char* strerror(int errnum) {
  /* TODO(alashkin): show real error message */
  const char frmstr[] = "Error: %d";
  static char retbuf[sizeof(frmstr) + 11];

  snprintf(retbuf, sizeof(retbuf), frmstr, errnum);
  return retbuf;
}

/*
 * Returns the number of seconds since the Arduino board
 * began running the current program.
 * So, this function
 * 1. doesn't support anything but NULL as a parameter
 * 2. suitable only to detect timeouts etc.
 * If time(NULL) is logged, result would be something
 * like "1970-01-01..." etc)
 */

time_t time(time_t* timer) {
  return millis() / 1000;
}
/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include <Arduino.h>
#include <Ethernet.h>
#include <utility/w5100.h>
#include <Dns.h>
#include <errno.h>

#ifndef W5100_CONNECT_TIMEOUT
#define W5100_CONNECT_TIMEOUT 10
#endif

/* at leat ATmega2560 uses little-endian model */
#define SWAP_UINT16(uint16) ((uint16 >> 8) | (uint16 << 8))
#define SWAP_UINT32(uint32)                               \
  (((uint32 >> 24) & 0xff) | ((uint32 << 8) & 0xff0000) | \
   ((uint32 >> 8) & 0xff00) | ((uint32 << 24) & 0xff000000))

uint16_t htons(uint16_t hostshort) {
  return SWAP_UINT16(hostshort);
}

uint32_t htonl(uint32_t hostlong) {
  return SWAP_UINT32(hostlong);
}

uint16_t ntohs(uint16_t netshort) {
  return SWAP_UINT16(netshort);
}

uint32_t ntohl(uint32_t netlong) {
  return SWAP_UINT32(netlong);
}

void FD_ZERO(fd_set* s) {
  memset(s, 0, sizeof(*s));
}

int FD_ISSET(sock_t fd, fd_set* set) {
  uint8_t i;
  for (i = 0; i != set->fd_count; i++) {
    if (set->fd_array[i] == fd) {
      return 1;
    }
  }
  return 0;
}

void FD_SET(sock_t fd, fd_set* set) {
  if (FD_ISSET(fd, set) == 0) {
    set->fd_array[set->fd_count++] = fd;
  }
}

char* inet_ntoa(struct in_addr in) {
  static char retbuf[16];

  snprintf(retbuf, sizeof(retbuf), "%hhu.%hhu.%hhu.%hhu", *(char*) &in,
           *((char*) &in + 1), *((char*) &in + 2), *((char*) &in + 3));

  return retbuf;
}

const char* inet_ntop(int af, const void* src, char* dst, socklen_t size) {
  if (size < 16) {
    return NULL;
  }

  strncpy(dst, inet_ntoa(*(struct in_addr*) src), size);

  return dst;
}

enum socketstatus {
  ssEmpty,
  ssReady,
  ssConnecting,
  ssNotInited,
  ssSending,
  ssListening
};

typedef SOCKET W5100_raw_sock_t;

typedef struct _W5100_raw_sock_t {
  W5100_raw_sock_t sockid;
  uint8_t protocol;
  uint16_t port;
  socketstatus status;
  time_t connect_start;

  struct peer_info {
    in_addr_t addr;
    in_port_t port;
  } peer_info;
} W5100_sock_t;

#ifdef AVR_ENABLE_DEBUG
void DumpSocket(W5100_sock_t* s) {
  Serial.print("SrSN: ");
  Serial.print(W5100.readSnSR(s->sockid), HEX);
  Serial.print(" SrIR: ");
  Serial.println(W5100.readSnIR(s->sockid), HEX);
}

#define DUMPSOCKET(s) DumpSocket(s)
#else
#define DUMPSOCKET(s)
#endif

W5100_sock_t g_sock_slots[MAX_SOCK_NUM];

W5100_sock_t* W5100_get_sock() {
  W5100_raw_sock_t s;
  unsigned int i;

  /*
   * W5100 allows to open only for sockets
   * so, everytime we need new - looking for free one
   */
  for (s = 0; s < MAX_SOCK_NUM; s++) {
    if (W5100.readSnSR(s) == SnSR::CLOSED) {
      break;
    }
  }

  if (s == MAX_SOCK_NUM) {
    return NULL;
  }

  for (i = 0; i < MAX_SOCK_NUM; i++) {
    if (g_sock_slots[i].status == ssEmpty) {
      g_sock_slots[i].sockid = s;
      g_sock_slots[i].status = ssNotInited;

      return &g_sock_slots[i];
    }
  }

  return NULL;
}

void W5100_completesockinit(W5100_sock_t* sock, uint16_t port) {
  if (sock->status != ssNotInited) {
    return;
  }

  if (port == 0) {
    sock->port = sock->sockid + 8888;
  } else {
    sock->port = port;
  }

  W5100.writeSnMR(sock->sockid, sock->protocol);
  W5100.writeSnPORT(sock->sockid, sock->port);

  W5100.execCmdSn(sock->sockid, Sock_OPEN);

  sock->status = ssReady;

  DUMPSOCKET(sock);
}

int W5100_issocketreadable(sock_t s) {
  W5100_sock_t* sock = (W5100_sock_t*) s;

  uint16_t snsr = W5100.readSnSR(sock->sockid);

  switch (sock->status) {
    case ssReady: {
      return W5100.getRXReceivedSize(sock->sockid) > 0;
    }
    case ssListening: {
      return (snsr & SnSR::ESTABLISHED) == SnSR::ESTABLISHED;
    }
    default:
      // the rest is not read-ready
      return 0;
  }
}

int W5100_isconnectcomplete(sock_t s) {
  W5100_sock_t* sock = (W5100_sock_t*) s;
  uint16_t snsr;

  if (sock->status != ssConnecting) {
    return 1;  // let it be complete
  };

  snsr = W5100.readSnSR(sock->sockid);

  if ((snsr & SnSR::ESTABLISHED) == SnSR::ESTABLISHED) {
    sock->status = ssReady;
    return 1;
  }

  return 0;
}

int W5100_issendcomplete(sock_t s) {
  W5100_sock_t* sock = (W5100_sock_t*) s;
  uint16_t snir;

  if (sock->status != ssSending) {
    return 1;  // ok, let it be complete
  }

  snir = W5100.readSnIR(sock->sockid);

  if ((snir & SnIR::SEND_OK) == SnIR::SEND_OK) {
    W5100.writeSnIR(sock->sockid, SnIR::SEND_OK);
    sock->status = ssReady;
    return 1;
  }

  if (snir & SnIR::TIMEOUT) {
    return -1;
  }

  return 0;
}

int W5100_issocketwritable(sock_t s) {
  W5100_sock_t* sock = (W5100_sock_t*) s;

  switch (sock->status) {
    case ssSending:
      W5100_issendcomplete(sock);
      break;
    case ssConnecting:
      W5100_isconnectcomplete(sock);
      break;
    default:
      /* there is no other -ing statuses now */
      break;
  }

  switch (sock->status) {
    case ssReady: {
      return W5100.getTXFreeSize(sock->sockid) > 0;
    }
    default: {
      /* the rest isn't write ready */
      return 0;
    }
  }
}

int W5100_issocketinerror(sock_t s) {
  W5100_sock_t* sock = (W5100_sock_t*) s;

  uint16_t snsr = W5100.readSnSR(sock->sockid);
  uint16_t snir = W5100.readSnIR(sock->sockid);

  switch (sock->status) {
    case ssSending: {
      if (snir & SnIR::TIMEOUT) {
        W5100.writeSnIR(sock->sockid, (SnIR::SEND_OK | SnIR::TIMEOUT));
        sock->status = ssReady;
        return 1;
      }
    }
    case ssConnecting: {
      if (time(NULL) - sock->connect_start > W5100_CONNECT_TIMEOUT) {
        sock->status = ssReady;
        return 1;
      }
    }
    case ssReady:
    case ssListening:
      return (snsr == SnSR::CLOSED) || (snsr == SnSR::CLOSING) ||
             (snsr == SnSR::CLOSE_WAIT);
    default:
      return -1;
  }
}

int getsockopt(sock_t s, int level, int optname, char* optval, int* optlen) {
  memset(optval, 0, *optlen);
  if (optname == SO_ERROR) {
    int res = W5100_issocketinerror(s);
    memcpy(optval, &res, *optlen);
  }
  return 0;
}

int sendto(sock_t s, const void* buf, size_t len, int flags,
           const struct sockaddr* name, socklen_t addr_len) {
  /* this version works with UDP only */
  W5100_sock_t* sock = (W5100_sock_t*) s;
  const sockaddr_in* addr = (const sockaddr_in*) name;
  uint8_t raw_addr[4];

  W5100_completesockinit(sock, 0);

  if (len > W5100.SSIZE) {
    errno = EMSGSIZE;
    return SOCKET_ERROR;
  }

  if (len > W5100.getTXFreeSize(sock->sockid)) {
    errno = EWOULDBLOCK;
    return SOCKET_ERROR;
  }

  raw_addr[0] = ((uint32_t) addr->sin_addr.s_addr & 0xFF);
  raw_addr[1] = ((uint32_t) addr->sin_addr.s_addr & 0xFFFF) >> 8;
  raw_addr[2] = ((uint32_t) addr->sin_addr.s_addr & 0xFFFFFF) >> 16;
  raw_addr[3] = (uint32_t) addr->sin_addr.s_addr >> 24;

  W5100.writeSnDIPR(sock->sockid, raw_addr);
  W5100.writeSnDPORT(sock->sockid, ntohs(addr->sin_port));
  W5100.send_data_processing(sock->sockid, (uint8_t*) buf, len);
  W5100.execCmdSn(sock->sockid, Sock_SEND);

  sock->status = ssSending;

  errno = 0;

  return len;
}

int listen(sock_t s, int backlog) {
  W5100_sock_t* sock = (W5100_sock_t*) s;
  (void) backlog;

  W5100.execCmdSn(sock->sockid, Sock_LISTEN);
  sock->status = ssListening;
  errno = 0;

  return 0;
}

int recv(sock_t s, char* buf, int len, int flags) {
  W5100_sock_t* sock = (W5100_sock_t*) s;
  int16_t aval_bytes = W5100.getRXReceivedSize(sock->sockid);

  if (aval_bytes == 0) {
    uint8_t status = W5100.readSnSR(sock->sockid);

    if (status == SnSR::LISTEN || status == SnSR::CLOSED ||
        status == SnSR::CLOSE_WAIT) {
      /* this is eof */
      return 0;
    } else {
      /* there's no data waiting to be read */
      errno = EWOULDBLOCK;
      return SOCKET_ERROR;
    }
  }

  if (len > aval_bytes) {
    len = aval_bytes;
  }

  W5100.recv_data_processing(sock->sockid, (unsigned char*) buf, len);
  W5100.execCmdSn(sock->sockid, Sock_RECV);
  W5100.writeSnIR(sock->sockid, SnIR::RECV);

  sock->status = ssReady;
  errno = 0;

  return len;
}

int send(sock_t s, const char* buf, int len, int flags) {
  W5100_sock_t* sock = (W5100_sock_t*) s;
  int16_t aval_bytes = W5100.getTXFreeSize(sock->sockid);

  if (aval_bytes == 0) {
    errno = EWOULDBLOCK;
    return SOCKET_ERROR;
  }

  if (len > aval_bytes) {
    len = aval_bytes;
  }

  W5100.send_data_processing(sock->sockid, (uint8_t*) buf, len);
  W5100.execCmdSn(sock->sockid, Sock_SEND);

  sock->status = ssSending;

  errno = 0;

  return len;
}

int recvfrom(sock_t s, char* buf, int len, int flags, struct sockaddr* from,
             int* fromlen) {
  /* this version works with UDP only */
  W5100_sock_t* sock = (W5100_sock_t*) s;
  struct sockaddr_in* addr = (struct sockaddr_in*) from;
  uint16_t bytes_to_read, aval_bytes = W5100.getRXReceivedSize(sock->sockid);
  uint16_t data_len = 0, ptr = 0;
  uint8_t udp_head[8];

  errno = 0;

  ptr = W5100.readSnRX_RD(sock->sockid);

  if (aval_bytes < sizeof(udp_head)) {
    /* we should have at least UDP header in recv buf */
    errno = EWOULDBLOCK;
    return SOCKET_ERROR;
  }

  W5100.read_data(sock->sockid, ptr, udp_head, 0x08);
  ptr += 8;

  if (addr != 0) {
    addr->sin_addr.s_addr =
        ((uint32_t) udp_head[3] << 24) | ((uint32_t) udp_head[2] << 16) |
        ((uint32_t) udp_head[1] << 8) | ((uint32_t) udp_head[0]);
    addr->sin_port = (udp_head[5] << 8) | udp_head[4];
  }

  bytes_to_read = data_len = (udp_head[6] << 8) | udp_head[7];

  if (data_len > (uint16_t) len) {
    bytes_to_read = len;
    errno = EMSGSIZE;
    /*
     * acoording specification recv should
     * drop data in this case
     */
  }

  W5100.read_data(sock->sockid, ptr, (uint8_t*) buf, bytes_to_read);

  ptr += bytes_to_read;

  W5100.writeSnRX_RD(sock->sockid, ptr);
  W5100.execCmdSn(sock->sockid, Sock_RECV);
  W5100.writeSnIR(sock->sockid, SnIR::RECV);

  sock->status = ssReady;

  return errno == 0 ? bytes_to_read : SOCKET_ERROR;
}

int connect(sock_t s, const struct sockaddr* name, int namelen) {
  W5100_sock_t* sock = (W5100_sock_t*) s;
  const sockaddr_in* addr = (const sockaddr_in*) name;
  uint8_t raw_addr[4];

  if (sock->port == 0) {
    W5100_completesockinit(sock, 0);
  }

  sock->peer_info.addr = addr->sin_addr.s_addr;
  sock->peer_info.port = addr->sin_port;

  raw_addr[0] = ((uint32_t) addr->sin_addr.s_addr & 0xFF);
  raw_addr[1] = ((uint32_t) addr->sin_addr.s_addr & 0xFFFF) >> 8;
  raw_addr[2] = ((uint32_t) addr->sin_addr.s_addr & 0xFFFFFF) >> 16;
  raw_addr[3] = (uint32_t) addr->sin_addr.s_addr >> 24;

  W5100.writeSnDIPR(sock->sockid, raw_addr);
  W5100.writeSnDPORT(sock->sockid, ntohs(addr->sin_port));

  W5100.execCmdSn(sock->sockid, Sock_CONNECT);

  /*
   * Looks like W5100 doesn't set TIMEOUT bit, so
   * we need to check connection time manually
   */

  sock->status = ssConnecting;
  sock->connect_start = time(NULL);

  errno = 0;

  return 0;
}

int closesocket(sock_t s) {
  W5100_sock_t* sock = (W5100_sock_t*) s;

  if (sock->status == ssSending) {
    while (W5100_issendcomplete(sock) == 0) {
      yield();
    }
  }

  W5100.execCmdSn(sock->sockid, Sock_CLOSE);
  W5100.writeSnIR(sock->sockid, 0xFF);

  memset(sock, 0, sizeof(*sock));

  sock->status = ssEmpty;

  return 0;
}

sock_t socket(int af, int type, int protocol) {
  static uint8_t W5100protocols[] = {SnMR::TCP, SnMR::UDP};

  /* IPv4 only, W5100 doesn't support IPv6 */
  if (af != AF_INET) {
    return INVALID_SOCKET;
  }

  /* autoselect from type only */
  if (protocol != 0) {
    return INVALID_SOCKET;
  }

  /* remapping type to protocol in W5100 terms */
  if (type < 0 ||
      (unsigned) type > sizeof(W5100protocols) / sizeof(W5100protocols[0])) {
    return INVALID_SOCKET;
  }

  W5100_sock_t* sock = W5100_get_sock();
  if (sock == NULL) {
    return INVALID_SOCKET;
  }

  sock->protocol = W5100protocols[type];
  sock->status = ssNotInited;

  /* that's all here since we don't have port number yet */
  return (void*) sock;
}

int getdnsname(char* name, size_t namelen) {
  IPAddress address = Ethernet.dnsServerIP();
  struct in_addr addr;
  addr.s_addr = address;
  snprintf(name, namelen, "udp://%s:53", inet_ntoa(addr));

  /* TODO(alashkin): add error checking */
  return 0;
}

struct hostent* gethostbyname(const char* name) {
  static hostent host;

  DNSClient dns;
  dns.begin(Ethernet.dnsServerIP());

  IPAddress address;
  dns.getHostByName(name, address);

  uint32_t tmp = address;
  memcpy(host.h_addr_list[0], &tmp, sizeof(tmp));

  return &host;
}

int bind(sock_t s, const struct sockaddr* name, int namelen) {
  W5100_sock_t* sock = (W5100_sock_t*) s;
  const struct sockaddr_in* addr = (const struct sockaddr_in*) name;

  W5100_completesockinit(sock, ntohs(addr->sin_port));

  return 0;
}

int getsockname(sock_t s, struct sockaddr* name, int* namelen) {
  W5100_sock_t* sock = (W5100_sock_t*) s;
  struct sockaddr_in* addr = (struct sockaddr_in*) name;

  if (sock->port == 0) {
    /* not initialized */
    errno = EINVAL;
    return SOCKET_ERROR;
  }

  addr->sin_port = htons(sock->port);
  addr->sin_family = AF_INET;

  return 0;
}

int getpeername(sock_t s, struct sockaddr* name, int* namelen) {
  W5100_sock_t* sock = (W5100_sock_t*) s;
  struct sockaddr_in* addr = (struct sockaddr_in*) name;

  if (sock->peer_info.port == 0) {
    errno = EINVAL;
    return SOCKET_ERROR;
  }

  memset(name, 0, *namelen);
  addr->sin_port = sock->peer_info.port;
  addr->sin_addr.s_addr = sock->peer_info.addr;
  addr->sin_family = AF_INET;

  return 0;
}

void W5100_restartlisten(W5100_sock_t* sock) {
  W5100.execCmdSn(sock->sockid, Sock_CLOSE);
  W5100.writeSnIR(sock->sockid, 0xFF);

  W5100.writeSnMR(sock->sockid, sock->protocol);
  W5100.writeSnPORT(sock->sockid, sock->port);
  W5100.execCmdSn(sock->sockid, Sock_OPEN);

  W5100.execCmdSn(sock->sockid, Sock_LISTEN);
  sock->status = ssListening;
}

sock_t accept(sock_t s, struct sockaddr* name, int* addrlen) {
  W5100_sock_t* sock = (W5100_sock_t*) s;
  struct sockaddr_in* addr = (struct sockaddr_in*) name;

  if ((W5100.readSnSR(sock->sockid) & SnSR::ESTABLISHED) != SnSR::ESTABLISHED) {
    errno = EWOULDBLOCK;
    return INVALID_SOCKET;
  }

  /*
   * Once listening socket gets a conection
   * it srops listen
   * so, we need to create atnother socket
   * and put it to listen mode
   */

  W5100_sock_t* new_sock = W5100_get_sock();
  if (new_sock == NULL) {
    /* if we don't have free sockets, reject connection */
    W5100_restartlisten(sock);

    errno = EWOULDBLOCK;
    return INVALID_SOCKET;
  } else {
    W5100_raw_sock_t tmp = new_sock->sockid;
    new_sock->sockid = sock->sockid;
    new_sock->protocol = sock->protocol;
    new_sock->port = 0xFFFF;
    new_sock->status = ssReady;

    /* change given sock_t and restart listening */
    sock->sockid = tmp;
    W5100_restartlisten(sock);

    /*
     * it seems, that the only way to get source addr & ip
     * is to parse headers,
     * but since fossa uses getpeername etc only for logging,
     * implementation is worth too much
     */
    addr->sin_port = 0xFFFF;
    addr->sin_addr.s_addr = 0xFFFFFFFF;
    new_sock->peer_info.port = addr->sin_port;
    new_sock->peer_info.addr = addr->sin_addr.s_addr;

    return new_sock;
  }
}

int select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds,
           const struct timeval* timeout) {
  uint32_t time_to_wait = 0;

  if (timeout != 0) {
    time_to_wait = timeout->tv_sec * 1000 + timeout->tv_usec;
  }

  fd_set out_readfds = {0};
  fd_set out_writefds = {0};
  fd_set out_exceptfds = {0};

  unsigned long start_time = millis();

  for (;;) {
    uint8_t i;

    if (readfds != NULL) {
      for (i = 0; i < readfds->fd_count; i++) {
        if (W5100_issocketreadable(readfds->fd_array[i])) {
          FD_SET(readfds->fd_array[i], &out_readfds);
        }
      }
    }

    if (writefds != NULL) {
      for (i = 0; i < writefds->fd_count; i++) {
        if (W5100_issocketwritable(writefds->fd_array[i])) {
          FD_SET(writefds->fd_array[i], &out_writefds);
        }
      }
    }

    if (exceptfds != NULL) {
      for (i = 0; i < exceptfds->fd_count; i++) {
        if (W5100_issocketinerror(exceptfds->fd_array[i])) {
          FD_SET(exceptfds->fd_array[i], &out_exceptfds);
        }
      }
    }

    /* check exit conditions */
    int ret =
        out_readfds.fd_count + out_writefds.fd_count + out_exceptfds.fd_count;

    if (ret != 0) {
      *readfds = out_readfds;
      *writefds = out_writefds;
      *exceptfds = out_exceptfds;

      return ret;
    }

    if (timeout != NULL && (millis() - start_time > time_to_wait)) {
      return 0;
    }

    yield();
  }
}

int avr_netinit(uint8_t* mac, uint8_t* ip) {
  unsigned int i;
  for (i = 0; i < MAX_SOCK_NUM; i++) {
    memset(&g_sock_slots[i], 0, sizeof(g_sock_slots[i]));
    g_sock_slots[i].status = ssEmpty;
  }

  IPAddress addr(ip[0], ip[1], ip[2], ip[3]);
  Ethernet.begin(mac, addr);

  return 0;
}

int fcntl(sock_t s, int cmd, ...) {
  /* Current implementation doesn't support blocking mode */
  return 0;
}

int setsockopt(sock_t s, int level, int optname, void* optval, int optlen) {
  return 0;
}
