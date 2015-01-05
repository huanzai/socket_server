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

#endif
