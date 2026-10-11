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
 * This file implements the CMU-TCP backend. The backend runs in a different
 * thread and handles all the socket operations separately from the application.
 *
 * This is where most of your code should go. Feel free to modify any function
 * in this file.
 */

#include "backend.h"

#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "cmu_packet.h"
#include "cmu_tcp.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

// Set to 0 to silence debug output. Output goes to stderr and is appended to
// DEBUG_LOG so it survives after the test kills the tmux session.
#define DEBUG 0
#define DEBUG_LOG "/tmp/cmu_tcp_debug.log"

static FILE* debug_log_file(void) {
  static FILE* f = NULL;
  if (f == NULL) {
    f = fopen(DEBUG_LOG, "a");
    if (f != NULL) setvbuf(f, NULL, _IOLBF, 0);
  }
  return f;
}

#define DEBUG_PRINT(...)                                \
  do {                                                  \
    if (DEBUG) {                                        \
      FILE* log_f = debug_log_file();                   \
      fprintf(stderr, "[%d %s] ", getpid(), __func__);  \
      fprintf(stderr, __VA_ARGS__);                     \
      if (log_f != NULL) {                              \
        fprintf(log_f, "[%d %s] ", getpid(), __func__); \
        fprintf(log_f, __VA_ARGS__);                    \
      }                                                 \
    }                                                   \
  } while (0)

void make_add_packet(uint8_t* data, int buf_len, cmu_socket_t* sock);
void add_to_buffer(cmu_socket_t* sock, unacked_packet* packet);
void send_logic(cmu_socket_t* sock);

/**
 * Tells if a given sequence number has been acknowledged by the socket.
 *
 * @param sock The socket to check for acknowledgements.
 * @param seq Sequence number to check.
 *
 * @return 1 if the sequence number has been acknowledged, 0 otherwise.
 */
int has_been_acked(cmu_socket_t* sock, uint32_t seq) {
  int result;
  result = after(sock->window.last_ack_received, seq);
  return result;
}

void send_flag_packet(uint8_t flags, cmu_socket_t* sock, uint32_t ack,
                      uint32_t seq) {
  socklen_t conn_len = sizeof(sock->conn);

  // No payload.
  uint8_t* payload = NULL;
  uint16_t payload_len = 0;

  // No extension.
  uint16_t ext_len = 0;
  uint8_t* ext_data = NULL;

  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen + payload_len;
  uint16_t adv_window = 1;
  uint8_t* response_packet =
      create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window, ext_len,
                    ext_data, payload, payload_len);

  DEBUG_PRINT("send flags=0x%x seq=%u ack=%u to port %u\n", flags, seq, ack,
              dst);
  sendto(sock->socket, response_packet, plen, 0,
         (struct sockaddr*)&(sock->conn), conn_len);
  free(response_packet);
}

/**
 * Updates the socket information to represent the newly received packet.
 *
 * In the current stop-and-wait implementation, this function also sends an
 * acknowledgement for the packet.
 *
 * @param sock The socket used for handling packets received.
 * @param pkt The packet data received by the socket.
 */
void handle_message(cmu_socket_t* sock, uint8_t* pkt) {
  cmu_tcp_header_t* hdr = (cmu_tcp_header_t*)pkt;
  uint8_t flags = get_flags(hdr);

  DEBUG_PRINT(
      "recv flags=0x%x seq=%u ack=%u hlen=%u plen=%u dst=%u "
      "(my_port=%u) is_connected=%d syn_rcvd=%d\n",
      flags, get_seq(hdr), get_ack(hdr), get_hlen(hdr), get_plen(hdr),
      get_dst(hdr), sock->my_port, sock->is_connected, sock->syn_rcvd);

  if (ntohl(hdr->identifier) != IDENTIFIER) {
    return;
  }

  switch (flags) {
    case SYN_FLAG_MASK: {
      bool well_formed =
          ((get_plen(hdr) == get_hlen(hdr)) && (sock->type == TCP_LISTENER));
      DEBUG_PRINT("SYN well_formed=%d\n", well_formed);
      if (well_formed) {
        sock->syn_rcvd = true;
        sock->window.next_seq_expected = get_seq(hdr) + 1;
      }
      break;
    }
    case (SYN_FLAG_MASK | ACK_FLAG_MASK): {
      bool well_formed = (sock->type == TCP_INITIATOR) &&
                         (sock->isn + 1 == get_ack(hdr)) &&
                         (get_plen(hdr) == get_hlen(hdr));
      DEBUG_PRINT("SYN-ACK well_formed=%d (expected ack=%u)\n", well_formed,
                  sock->window.last_ack_received + 1);
      if (well_formed) {
        uint32_t ack = get_ack(hdr);
        if (after(ack, sock->window.last_ack_received) &&
            !after(ack, sock->max_byte_sent)) {
          sock->window.last_ack_received = ack;
        }
        sock->window.next_seq_expected = get_seq(hdr) + 1;
        sock->is_connected = true;
        send_flag_packet(ACK_FLAG_MASK, sock, get_seq(hdr) + 1, get_ack(hdr));
      }
      break;
    }
    case ACK_FLAG_MASK: {
      uint32_t ack = get_ack(hdr);

      if (!sock->is_connected) {  // HANDSHAKE
        bool well_formed = (sock->type == TCP_LISTENER) &&
                           (get_ack(hdr) == sock->isn + 1) &&
                           (get_plen(hdr) == get_hlen(hdr));
        DEBUG_PRINT("handshake ACK well_formed=%d (expected ack=%u)\n",
                    well_formed, sock->isn + 1);
        if (well_formed) {
          sock->is_connected = true;
          if (after(ack, sock->window.last_ack_received) &&
              !after(ack, sock->max_byte_sent)) {
            sock->window.last_ack_received = ack;
          }
        }
        break;
      } else {  // REGULAR
        if (after(ack, sock->window.last_ack_received) &&
            !after(ack, sock->max_byte_sent)) {
          sock->window.last_ack_received = ack;
        }
      }
    }
    default: {
      if (sock->is_connected && (get_plen(hdr) > get_hlen(hdr))) {
        socklen_t conn_len = sizeof(sock->conn);
        uint32_t packet_seq = sock->window.last_ack_received;

        // No payload.
        uint8_t* payload = NULL;
        uint16_t payload_len = 0;

        // No extension.
        uint16_t ext_len = 0;
        uint8_t* ext_data = NULL;
        uint16_t src = sock->my_port;
        uint16_t dst = ntohs(sock->conn.sin_port);
        uint16_t hlen = sizeof(cmu_tcp_header_t);
        uint16_t plen = hlen + payload_len;
        uint8_t flags = ACK_FLAG_MASK;
        uint16_t adv_window = 1;

        // ack = what have we heard so far?
        uint32_t ack = sock->window.next_seq_expected;

        uint32_t seq = get_seq(hdr);

        if (seq == sock->window.next_seq_expected) {
          sock->window.next_seq_expected = seq + get_payload_len(pkt);
          ack = get_payload_len(pkt) + get_seq(hdr);
          payload_len = get_payload_len(pkt);
          payload = get_payload(pkt);

          // Make sure there is enough space in the buffer to store the payload.
          sock->received_buf =
              realloc(sock->received_buf, sock->received_len + payload_len);
          memcpy(sock->received_buf + sock->received_len, payload, payload_len);
          sock->received_len += payload_len;
        }

        uint8_t* response_packet =
            create_packet(src, dst, packet_seq, ack, hlen, plen, flags,
                          adv_window, ext_len, ext_data, payload, payload_len);

        sendto(sock->socket, response_packet, plen, 0,
               (struct sockaddr*)&(sock->conn), conn_len);
        free(response_packet);
      }
    }
  }
}

/**
 * Checks if the socket received any data.
 *
 * It first peeks at the header to figure out the length of the packet and then
 * reads the entire packet.
 *
 * @param sock The socket used for receiving data on the connection.
 * @param flags Flags that determine how the socket should wait for data. Check
 *             `cmu_read_mode_t` for more information.
 */
void check_for_data(cmu_socket_t* sock, cmu_read_mode_t flags) {
  cmu_tcp_header_t hdr;
  uint8_t* pkt;
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }
  switch (flags) {
    case NO_FLAG:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), MSG_PEEK,
                     (struct sockaddr*)&(sock->conn), &conn_len);
      break;
    case TIMEOUT: {
      // Using `poll` here so that we can specify a timeout.
      struct pollfd ack_fd;
      ack_fd.fd = sock->socket;
      ack_fd.events = POLLIN;
      // Timeout after DEFAULT_TIMEOUT.
      if (poll(&ack_fd, 1, DEFAULT_TIMEOUT) <= 0) {
        break;
      }
    }
    // Fallthrough.
    case NO_WAIT:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t),
                     MSG_DONTWAIT | MSG_PEEK, (struct sockaddr*)&(sock->conn),
                     &conn_len);
      break;
    default:
      perror("ERROR unknown flag");
  }
  if (len >= (ssize_t)sizeof(cmu_tcp_header_t)) {
    plen = get_plen(&hdr);
    pkt = malloc(plen);
    while (buf_size < plen) {
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0,
                   (struct sockaddr*)&(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }
    handle_message(sock, pkt);
    free(pkt);
  }
  pthread_mutex_unlock(&(sock->recv_lock));
}

// Send data in packet. You are guaranteed that packet.len < MSS
void send_packet(cmu_socket_t* sock, unacked_packet* packet) {
  uint8_t* msg;
  size_t conn_len = sizeof(sock->conn);
  int sockfd = sock->socket;

  if (packet->len > 0) {
    clock_gettime(CLOCK_MONOTONIC, &packet->send_time);
    uint16_t payload_len = packet->len;
    uint16_t src = sock->my_port;
    uint16_t dst = ntohs(sock->conn.sin_port);
    uint32_t seq = packet->start_byte;
    uint32_t ack = sock->window.next_seq_expected;
    uint16_t hlen = sizeof(cmu_tcp_header_t);
    uint16_t plen = hlen + payload_len;
    uint8_t flags = ACK_FLAG_MASK;
    uint16_t adv_window = 1;
    uint16_t ext_len = 0;
    uint8_t* ext_data = NULL;
    uint8_t* payload = packet->data;

    msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                        ext_len, ext_data, payload, payload_len);

    sendto(sockfd, msg, plen, 0, (struct sockaddr*)&(sock->conn), conn_len);
    free(msg);

    uint32_t end_byte = packet->start_byte + packet->len;
    if (after(end_byte, sock->max_byte_sent)) {
      sock->max_byte_sent = end_byte;
    }
  }
}

/**
 * Break up the data into packets and store into unacked.
 *
 * You should most certainly update this function in your implementation.
 *
 * @param sock The socket to use for sending data.
 * @param data The data to be sent.
 * @param buf_len The length of the data being sent.
 */
void break_into_packets(cmu_socket_t* sock, uint8_t* data, int buf_len) {
  uint8_t* data_offset = data;

  if (buf_len > 0) {
    while (buf_len != 0) {
      uint16_t payload_len = MIN((uint32_t)buf_len, (uint32_t)MSS);
      uint8_t* payload = data_offset;
      make_add_packet(payload, payload_len, sock);

      buf_len -= payload_len;
      data_offset += payload_len;
    }
  }
}

void handshake(cmu_socket_t* sock) {
  sock->is_connected = false;
  sock->syn_rcvd = false;

  if (sock->type == TCP_INITIATOR) {
    // Send initial SYN
    sock->isn = rand();
    sock->window.last_ack_received = sock->isn;
    sock->max_byte_sent = sock->isn + 1;  // the SYN occupies isn
    while (!sock->is_connected) {
      send_flag_packet(SYN_FLAG_MASK, sock, 0, sock->isn);
      check_for_data(sock, TIMEOUT);  // waits up to DEFAULT_TIMEOUT (3s)
    }
  } else {  // TCP_LISTENER
    sock->isn = rand();
    sock->max_byte_sent = sock->isn + 1;  // the SYN-ACK occupies isn
    while (!sock->is_connected) {
      if (sock->syn_rcvd) {
        send_flag_packet(ACK_FLAG_MASK | SYN_FLAG_MASK, sock,
                         sock->window.next_seq_expected, sock->isn);
      }
      check_for_data(
          sock,
          TIMEOUT);  // wait for a SYN; handle_message replies with SYN-ACK
    }
  }
}

double get_time_passed(struct timespec start, struct timespec end) {
  return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
}

void make_add_packet(uint8_t* data, int buf_len, cmu_socket_t* sock) {
  unacked_packet* packet = malloc(sizeof(unacked_packet));

  // store data
  uint8_t* temp = malloc(buf_len);
  memcpy(temp, data, buf_len);
  packet->data = temp;
  packet->len = buf_len;

  // add to buffer
  add_to_buffer(sock, packet);
}

void add_to_buffer(cmu_socket_t* sock, unacked_packet* packet) {
  unacked_buffer* unacked = &sock->unacked;

  // Resize if size = capacity. Only the live entries (start_idx onwards) are
  // copied, so the new array starts at index 0 again.
  if (unacked->size + 1 > unacked->capacity) {
    uint32_t new_capacity = unacked->capacity * 2;
    if (new_capacity < unacked->size + 1) {
      new_capacity = (unacked->size + 1) * 2;
    }
    unacked_packet** temp = malloc(sizeof(unacked_packet*) * new_capacity);
    for (uint32_t i = 0; i < unacked->size; i++) {
      temp[i] = unacked->buffer[unacked->start_idx + i];
    }
    free(unacked->buffer);
    unacked->buffer = temp;
    unacked->capacity = new_capacity;
    unacked->last_sent -= (int32_t)unacked->start_idx;
    unacked->start_idx = 0;
  }

  // Add new packet
  if (unacked->size == 0) {
    packet->start_byte = sock->window.last_ack_received;
  } else {
    uint32_t last_idx = unacked->start_idx + unacked->size - 1;
    unacked_packet* last_packet = unacked->buffer[last_idx];
    packet->start_byte = last_packet->start_byte + last_packet->len;
  }
  unacked->buffer[unacked->start_idx + unacked->size] = packet;
  unacked->size += 1;
}

void init_unacked_buffer(cmu_socket_t* sock) {
  sock->unacked.last_sent = -1;
  sock->unacked.buffer = malloc(5 * sizeof(unacked_packet*));
  sock->unacked.capacity = 5;
  sock->unacked.size = 0;
  sock->unacked.start_idx = 0;
  sock->window.len = 0;
}

bool timer_expired(cmu_socket_t* sock) {
  // Nothing in flight: the first packet hasn't been sent, so it has no timer.
  if (sock->unacked.size == 0 ||
      sock->unacked.last_sent < (int32_t)sock->unacked.start_idx) {
    return false;
  }

  struct timespec start =
      sock->unacked.buffer[sock->unacked.start_idx]->send_time;
  struct timespec end;
  clock_gettime(CLOCK_MONOTONIC, &end);
  double time_diff = get_time_passed(start, end);  // seconds

  return time_diff * 1000.0 > DEFAULT_TIMEOUT;  // DEFAULT_TIMEOUT is in ms
}

void timer_logic(cmu_socket_t* sock) {
  if (timer_expired(sock)) {
    // resend window
    sock->unacked.last_sent = (int32_t)sock->unacked.start_idx - 1;
    sock->window.len = 0;
    send_logic(sock);
  }
}

// check unacked and send anything not yet send respecting window size
void send_logic(cmu_socket_t* sock) {
  unacked_buffer* unacked = &sock->unacked;

  if (unacked->size == 0) {
    return;  // nothing to send!
  }

  while (1) {
    uint32_t send_idx = (uint32_t)(unacked->last_sent + 1);
    bool out_of_range = send_idx >= unacked->start_idx + unacked->size;
    if (out_of_range) {
      break;
    }

    uint32_t next_plen = unacked->buffer[send_idx]->len;
    bool fits_window = (sock->window.len + next_plen) <= CP1_WINDOW_SIZE;
    if (!fits_window) {
      break;
    }

    // send next packet
    send_packet(sock, unacked->buffer[send_idx]);
    unacked->last_sent += 1;
    sock->window.len += next_plen;
  }
}

void free_packet(unacked_packet* packet) {
  free(packet->data);
  free(packet);
}

void update_unacked(cmu_socket_t* sock) {
  while (sock->unacked.size > 0) {
    // check off by one for window
    uint32_t start_idx = sock->unacked.start_idx;
    uint32_t first_packet_start = sock->unacked.buffer[start_idx]->start_byte;
    if (first_packet_start == sock->window.last_ack_received) break;

    // delete first packet
    unacked_packet* packet = sock->unacked.buffer[start_idx];
    sock->window.len -= packet->len;
    free_packet(packet);  // CAUTION: don't access packet after this
    sock->unacked.buffer[start_idx] = NULL;

    sock->unacked.size -= 1;
    sock->unacked.capacity -= 1;
    sock->unacked.start_idx += 1;
  }
}

// The application is done writing, but packets may still be in flight. Keep
// sending, receiving ACKs, and checking the timer until every packet in the
// unacked buffer has been acked (which also leaves window.len at 0).
void flush_unacked(cmu_socket_t* sock) {
  while (sock->unacked.size > 0) {
    send_logic(sock);
    check_for_data(sock, NO_WAIT);
    update_unacked(sock);
    timer_logic(sock);
  }
}

/*void teardown(sock){
  sock->fin_rcvd = false;

  if (sock->type == TCP_INITIATOR) {
    // Send initial FIN
    sock->isn = rand();
    sock->window.last_ack_received = sock->isn;
    sock->max_byte_sent = sock->isn + 1;  // the SYN occupies isn
    while (!sock->is_connected) {
      send_flag_packet(SYN_FLAG_MASK, sock, 0, sock->isn);
      check_for_data(sock, TIMEOUT);  // waits up to DEFAULT_TIMEOUT (3s)
    }
  } else {  // TCP_LISTENER
    sock->isn = rand();
    sock->max_byte_sent = sock->isn + 1;  // the SYN-ACK occupies isn
    while (!sock->is_connected) {
      if (sock->syn_rcvd) {
        send_flag_packet(ACK_FLAG_MASK | SYN_FLAG_MASK, sock,
                         sock->window.next_seq_expected, sock->isn);
      }
      check_for_data(
          sock,
          TIMEOUT);  // wait for a SYN; handle_message replies with SYN-ACK
    }
  }
  // send FIN

  // resend if no ACK

  // wait 2 × MSL (Maximum Segment Lifetime) from confirmation
}*/

void* begin_backend(void* in) {
  cmu_socket_t* sock = (cmu_socket_t*)in;
  int death, buf_len, send_signal;
  uint8_t* data;
  srand(time(NULL) * sock->my_port);
  init_unacked_buffer(sock);

  handshake(sock);

  while (1) {
    while (pthread_mutex_lock(&(sock->death_lock)) != 0) {
    }
    death = sock->dying;
    pthread_mutex_unlock(&(sock->death_lock));

    while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
    }
    buf_len = sock->sending_len;

    if (death && buf_len == 0) {
      pthread_mutex_unlock(&(sock->send_lock));
      flush_unacked(sock);
      // teardown(sock);
      break;
    }

    update_unacked(sock);
    timer_logic(sock);

    // extract the data
    if (buf_len > 0) {
      data = malloc(buf_len);
      memcpy(data, sock->sending_buf, buf_len);
      break_into_packets(sock, data, buf_len);
      sock->sending_len = 0;
      free(sock->sending_buf);
      free(data);
      sock->sending_buf = NULL;
      pthread_mutex_unlock(&(sock->send_lock));
    } else {
      pthread_mutex_unlock(&(sock->send_lock));
    }

    // send anything in our unacked buffer that fits the window
    send_logic(sock);

    check_for_data(sock, NO_WAIT);

    while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
    }

    send_signal = sock->received_len > 0;

    pthread_mutex_unlock(&(sock->recv_lock));

    if (send_signal) {
      pthread_cond_signal(&(sock->wait_cond));
    }
  }

  pthread_exit(NULL);
  return NULL;
}
