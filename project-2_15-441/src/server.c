/**
 * Copyright (C) 2022 Carnegie Mellon University
 *
 * This file is part of the TCP in the Wild course project developed for the
 * Computer Networks course (15-441/641) taught at Carnegie Mellon University.
 *
 * No part of the project may be copied and/or distributed without the express
 * permission of the 15-441/641 course staff.
 *
 *
 * This file implements a simple CMU-TCP server. Its purpose is to provide
 * simple test cases and demonstrate how the sockets will be used.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "cmu_tcp.h"

#define BUF_SIZE 10000

/*
 * Param: sock - used for reading and writing to a connection
 *
 * Purpose: To provide some simple test cases and demonstrate how
 *  the sockets will be used.
 *
 */
void functionality(cmu_socket_t *sock) {
  uint8_t buf[BUF_SIZE];
  FILE *fp;
  int n;

  // The client's greeting is exactly 229 bytes, then 9 bytes after our reply.
  // Read exactly those amounts so no file bytes are consumed here.
  int got = 0;
  while (got < 229) {
    n = cmu_read(sock, buf, 229 - got, NO_FLAG);
    if (n <= 0) return;
    got += n;
  }
  printf("Greeting 1: %d bytes\n", got);
  cmu_write(sock, "hi there", 9);
  got = 0;
  while (got < 9) {
    n = cmu_read(sock, buf, 9 - got, NO_FLAG);
    if (n <= 0) return;
    got += n;
  }
  printf("Greeting 2: %d bytes\n", got);
  cmu_write(sock, "https://www.youtube.com/watch?v=dQw4w9WgXcQ", 44);

  // Read until the whole file has arrived, timing the file transfer only
  // (excludes the handshake, greeting exchange, and teardown).
  char *env_bytes = getenv("FILE_BYTES");
  int expected = env_bytes ? atoi(env_bytes) : 1048576;
  int total = 0;
  struct timespec t_start, t_end;
  fp = fopen("/tmp/file.c", "w");
  clock_gettime(CLOCK_MONOTONIC, &t_start);
  while (total < expected) {
    n = cmu_read(sock, buf, BUF_SIZE, NO_FLAG);
    if (n <= 0) break;
    fwrite(buf, 1, n, fp);
    total += n;
  }
  clock_gettime(CLOCK_MONOTONIC, &t_end);
  fclose(fp);
  double secs = (t_end.tv_sec - t_start.tv_sec) +
                (t_end.tv_nsec - t_start.tv_nsec) / 1e9;
  printf("Received %d of %d bytes\n", total, expected);
  printf("RESULT bytes=%d seconds=%.6f\n", total, secs);
  fflush(stdout);
}

int main() {
  int portno;
  char *serverip;
  char *serverport;
  cmu_socket_t socket;

  serverip = getenv("server15441");
  if (!serverip) {
    serverip = "10.0.1.1";
  }

  serverport = getenv("serverport15441");
  if (!serverport) {
    serverport = "15441";
  }
  portno = (uint16_t)atoi(serverport);

  if (cmu_socket(&socket, TCP_LISTENER, portno, serverip) < 0) {
    exit(EXIT_FAILURE);
  }

  functionality(&socket);

  if (cmu_close(&socket) < 0) {
    exit(EXIT_FAILURE);
  }

  return EXIT_SUCCESS;
}
