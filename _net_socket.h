#ifndef SOCKET_H
#define SOCKET_H

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

struct socket_msg_data {
    int id; 
    int buf_len;
    char *buf;
};

struct socket_server;
typedef struct socket_server socket_server;
typedef void (*msg_func)(struct socket_msg_data*);

socket_server *socket_server_create(msg_func f); 
void socket_server_poll(socket_server* ss);

void listen_socket(socket_server *ss, int port);
void connect_socket(socket_server *ss, char *ip, int ip_len, int port);
void write_socket(socket_server *ss, int id, char *msg, int msg_len);
void close_socket(socket_server *ss, int id);

#endif
