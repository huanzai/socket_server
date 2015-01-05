#include <sys/epoll.h>

#include "_net_poll.h"
#include "_net_socket.h"

int
sp_create(int size) {
	return epoll_create(size);
}

int 
sp_wait(int efd, struct event *ev, int maxevs) {
	int i,n;
	struct epoll_event events[maxevs];
	
	n = epoll_wait(efd, events, maxevs, -1);
	for (i = 0; i < n; i++) {
		if (events[i].events & EPOLLIN) {
			ev[i].is_read = 1;
		}
		if (events[i].events & EPOLLOUT) {
			ev[i].is_write = 1;
		}
		ev[i].s = events[i].data.ptr;
	}
	return n;
}

int
sp_add(int efd, int fd, void *s) {
	struct epoll_event ev;
	ev.events 	= EPOLLIN;
	ev.data.ptr = s;
	return epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
}

int 
sp_write(int efd, int fd, void *s) {
	struct epoll_event ev;
	ev.events   = EPOLLIN | EPOLLOUT;
	ev.data.ptr = s;
	return epoll_ctl(efd, EPOLL_CTL_MOD, fd, &ev);
}

int
sp_unwrite(int efd, int fd, void *s) {
	struct epoll_event ev;
	ev.events 	= EPOLLIN;
	ev.data.ptr = s;
	return epoll_ctl(efd, EPOLL_CTL_MOD, fd, &ev);
}

int
sp_del(int efd, int fd) {
	return epoll_ctl(efd, EPOLL_CTL_DEL, fd, 0);	
}

