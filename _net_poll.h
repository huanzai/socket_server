#ifndef NET_POLL_H
#define NET_POLL_H

struct event;

int sp_create(int size);
int sp_wait(int efd, struct event *ev, int maxevs);

int sp_add(int efd, int fd, void *s);
int sp_write(int efd, int fd, void *s);
int sp_unwrite(int efd, int fd, void *s);
int sp_del(int efd, int fd);

#endif
