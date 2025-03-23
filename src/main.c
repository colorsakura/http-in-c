#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* 内存池 */
#define DEFAULT_MEM_POOL_SIZE (16 * 1024)
#define MEM_POOL_ALIGNMENT 16
#define MEM_ALIGNMENT sizeof(unsigned long)

#define BUFFER_SIZE 256

typedef struct mem_pool_s mem_pool_t;
typedef struct mem_pool_large_s mem_pool_large_t;
typedef struct mem_pool_data_s mem_pool_data_t;

struct mem_pool_large_s {
  mem_pool_large_t *next;
  void *alloc;
};

struct mem_pool_data_s {
  u_char *last; // 当前使用位置
  u_char *end;  // 块末尾
  mem_pool_t *next;
  int failed;
};

struct mem_pool_s {
  mem_pool_data_t d;
  size_t max;
  mem_pool_t *current;
  mem_pool_large_t *large;
};

mem_pool_t *mem_pool_create(size_t size);
void mem_pool_destroy(mem_pool_t *pool);
static void *mem_malloc_small(mem_pool_t *pool, size_t size);
static void *mem_malloc_block(mem_pool_t *pool, size_t size);
static void *mem_malloc_large(mem_pool_t *pool, size_t size);
void *mem_malloc(mem_pool_t *pool, size_t size);
void mem_free(mem_pool_t *pool, void *p);

mem_pool_t *mem_pool_create(size_t size) {
  mem_pool_t *p;

  int err = posix_memalign((void **)&p, MEM_POOL_ALIGNMENT, size);
  if (err) {
    fprintf(stderr, "posix_memalign failed\n");
    return NULL;
  }

  p->d.last = (u_char *)p + sizeof(mem_pool_t);
  p->d.end = (u_char *)p + size;
  p->d.next = NULL;
  p->d.failed = 0;

  p->max = size - sizeof(mem_pool_t);

  p->current = p;
  p->large = NULL;

  return p;
}

void mem_pool_destroy(mem_pool_t *pool) {
  for (mem_pool_large_t *large = pool->large; large; large = large->next) {
    free(large->alloc);
  }

  for (mem_pool_t *p = pool, *n = pool->d.next;; p = n, n = n->d.next) {
    free(p);
    if (n == NULL) {
      break;
    }
  }
}

void *mem_malloc(mem_pool_t *pool, size_t size) {
  if (size <= pool->max) {
    return mem_malloc_small(pool, size);
  }

  return mem_malloc_large(pool, size);
}

void mem_free(mem_pool_t *pool, void *p) {}

static inline void *mem_malloc_small(mem_pool_t *pool, size_t size) {
  mem_pool_t *p = pool->current;

  do {
    u_char *m = p->d.last;

    if ((size_t)(p->d.end - m) >= size) {
      p->d.last = m + size;

      return m;
    }

    p = p->d.next;

  } while (p);

  return mem_malloc_block(pool, size);
}

static void *mem_malloc_block(mem_pool_t *pool, size_t size) {
  u_char *m;
  mem_pool_t *p;

  size_t psize = (size_t)(pool->d.end - (u_char *)pool);

  int err = posix_memalign((void **)&m, MEM_POOL_ALIGNMENT, psize);
  if (err) {
    fprintf(stderr, "posix_memalign failed\n");
    return NULL;
  }

  mem_pool_t *new = (mem_pool_t *)m;

  new->d.end = m + psize;
  new->d.next = NULL;
  new->d.failed = 0;

  m += sizeof(mem_pool_data_t);
  new->d.last = m + size;

  for (p = pool->current; p->d.next; p = p->d.next) {
    if (p->d.failed++ > 4) {
      pool->current = p->d.next;
    }
  }

  p->d.next = new;

  return m;
}

static void *mem_malloc_large(mem_pool_t *pool, size_t size) {
  void *p = malloc(size);
  if (!p) {
    return NULL;
  }

  int n = 0;

  mem_pool_large_t *large;
  for (large = pool->large; large; large = large->next) {
    if (large->alloc == NULL) {
      large->alloc = p;
      return p;
    }

    if (n++ > 3) {
      break;
    }
  }

  large = mem_malloc_small(pool, sizeof(mem_pool_large_t));
  if (large == NULL) {
    free(p);
    return NULL;
  }

  large->alloc = p;
  large->next = pool->large;
  pool->large = large;

  return p;
}

/* Event loop */

typedef struct e_loop_s e_loop_t;

struct e_loop_s {};

/* HTTP */

#define CR '\r'
#define LF '\n'

#define HTTP_UNKNOWN 0
#define HTTP_GET 1
#define HTTP_PUT 2
#define HTTP_POST 3

#define HTTP_PARSE_INVALID_METHOD 0
#define HTTP_PARSE_INVALID_REQUEST 1
#define HTTP_PARSE_INVALID_VERSION 2

typedef struct http_connection_s {
  void *data;

  mem_pool_t *pool;

  int fd;

  struct sockaddr *addr;
  socklen_t socklen;
} http_connection_t;

typedef struct http_request_s {
  uint32_t signature;

  http_connection_t *connection;

  mem_pool_t *pool;

  int state;

  int method;

  u_char *method_start;
  u_char *method_end;
} http_request_t;

typedef struct buf_s {
  u_char *pos;
  u_char *last;

  u_char *start;
  u_char *end;
} buf_t;

static http_request_t *http_alloc_request(http_connection_t *c) {
  http_request_t *r = mem_malloc(c->pool, sizeof(http_request_t));
  if (r == NULL) {
    return NULL;
  }

  r->pool = c->pool;

  return r;
}

int http_parse_request_line(http_request_t *r, buf_t *b) {
  enum {
    sw_start = 0,
    sw_method,
    sw_space_before_url,
    sw_path,
    sw_http_version,
  } state;

  state = r->state;

  for (u_char *p = b->pos; p < b->last; p++) {
    char ch = *p;

    switch (state) {
    case sw_start:
      r->method_start = p;

      if (ch == CR || ch == LF) {
        break;
      }

      if (ch < 'A' || ch > 'Z') {
        return HTTP_PARSE_INVALID_METHOD;
      }

      state = sw_method;
      break;

    case sw_method:
      if (ch == ' ') {
        r->method_end = p - 1;
        u_char *m = r->method_start;

        switch (p - m) {
        case 3:
          if (memcmp(m, "GET", 3) == 0) {
            r->method = HTTP_GET;
            break;
          }

          if (memcmp(m, "PUT", 3) == 0) {
            r->method = HTTP_PUT;
            break;
          }

          break;

        default:
          r->method = HTTP_UNKNOWN;
          break;
        }

        state = sw_space_before_url;
        break;
      }

      if (ch < 'A' || ch > 'Z') {
        return HTTP_PARSE_INVALID_METHOD;
      }

      break;

    case sw_space_before_url:
      break;

    case sw_path:

    case sw_http_version:

    default:
      break;
    }
  }

  return 0;
}

int main(int argc, char **argv) {
  int ret = 0;
  static const char *hello = "HTTP/1.0 200 OK\r\n\r\nHello World!";

  int tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (tcp_socket < 0) {
    fprintf(stderr, "socket");
    return -1;
  }
  printf("socket creation succeeded\n");

  setsockopt(tcp_socket, SOL_SOCKET, SO_REUSEADDR, &ret, sizeof(ret));

  struct sockaddr_in bind_addr;
  memset(&bind_addr, 0, sizeof(bind_addr));
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_port = htons(18080);
  bind_addr.sin_addr.s_addr = INADDR_ANY;

  int rc =
      bind(tcp_socket, (const struct sockaddr *)&bind_addr, sizeof(bind_addr));
  if (rc < 0) {
    fprintf(stderr, "bind() failed\n");
    ret = -1;
    goto exit;
  }
  printf("bind() succeeded\n");

  rc = listen(tcp_socket, 5);
  if (rc < 0) {
    fprintf(stderr, "listen() failed\n");
    ret = -1;
    goto exit;
  }
  printf("listen() succeeded\n");

  for (;;) {
    mem_pool_t *pool = mem_pool_create(DEFAULT_MEM_POOL_SIZE);
    if (pool == NULL) {
      fprintf(stderr, "mem_pool_create() failed\n");
      goto exit;
    }

    http_connection_t *c = mem_malloc(pool, sizeof(http_connection_t));
    if (c == NULL) {
      fprintf(stderr, "mem_malloc() failed\n");
      goto close;
    }

    c->pool = pool;

    printf("waiting for connection...\n");
    c->fd = accept(tcp_socket, c->addr, &c->socklen);

    printf("got a connection\n");

    size_t total_bytes_read = 0, bytes_read = 0;
    u_char *buffer = mem_malloc(pool, BUFFER_SIZE);
    if (buffer == NULL) {
      fprintf(stderr, "Failed to allocate buffer\n");
      goto close;
    }

    int n = 1;
    for (;;) {
      bytes_read = read(c->fd, buffer + total_bytes_read,
                        BUFFER_SIZE * n - total_bytes_read);

      if (bytes_read < 0) {
        fprintf(stderr, "Failed to read from socket\n");
        goto close;
      }

      if (bytes_read == 0) {
        // Connection closed by client
        break;
      }

      total_bytes_read += bytes_read;

      if (total_bytes_read == BUFFER_SIZE * n) {
        n++;
        // Buffer is full, reallocate
        u_char *new_buffer = mem_malloc(pool, BUFFER_SIZE * n);
        if (new_buffer == NULL) {
          fprintf(stderr, "Failed to reallocate buffer\n");
          goto close;
        }
        memcpy(new_buffer, buffer, total_bytes_read);
        // mem_free(pool, buffer);
        buffer = new_buffer;
      } else {
        // Data is read
        break;
      }
    }
    printf("read %zd type of buffer: %s\n", total_bytes_read, buffer);

    http_alloc_request(c);

    write(c->fd, hello, strlen(hello));

  close:
    close(c->fd);
    mem_pool_destroy(pool);
  }

exit:
  close(tcp_socket);
  return ret;
}
