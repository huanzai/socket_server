#ifndef SOCKET_H
#define SOCKET_H

#include <netinet/in.h>

struct socket {
    int id; 
    int type;
    int fd; 
    int buf_len;
    char *buf;
};

struct event {
    struct socket *s; 
    int is_write;
    int is_read;
};

#define SOCKET_MSG_ACCEPT 1
#define SOCKET_MSG_CONNECT 2
#define SOCKET_MSG_DATA 3
#define SOCKET_MSG_CLOSE 4

struct socket_msg_accept {
    int id; 
    struct sockaddr_in addr;
};

struct socket_msg_connect {
    int id; 
    struct sockaddr_in addr;
};

struct socket_msg_close {
    int id; 
};

struct socket_msg_data {
    int id; 
    int buf_len;
    char *buf;
};

struct socket_server;
typedef struct socket_server socket_server;
typedef void (*msg_func)(int type, void*msg, int msg_len);

socket_server *socket_server_create(msg_func f); 
void socket_server_poll(socket_server* ss);

void listen_socket(socket_server *ss, int port);
void connect_socket(socket_server *ss, char *ip, int ip_len, int port);
void write_socket(socket_server *ss, int id, char *msg, int msg_len);
void close_socket(socket_server *ss, int id);

#endif
