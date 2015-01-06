#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "_net_poll.h"
#include "_net_socket.h"

#define MAX_EVENTS 64

#define MAX_READ_SIZE 4096 

#define SOCKET_TYPE_ACCEPT 1
#define SOCKET_TYPE_CONNECT 2
#define SOCKET_TYPE_LISTEN 3

#define SOCKET_MSG_ACCEPT 1
#define SOCKET_MSG_CONNECT 2
#define SOCKET_MSG_DATA 3

struct socket_server {
	int efd;
	int read_fd;
	int write_fd;
	int ctrl_index;
	int ctrl_size;
	struct event ctrl_ev[MAX_EVENTS];
	int sk_use;
	int sk_cap;
	struct socket **sk;
	int atinc_id;
	msg_func msg_push;	
	int check_cmd;
	pthread_mutex_t cmd_lock;
};

int _server_delfd(struct socket_server *ss, struct socket *s);
int _server_addfd(struct socket_server *ss, int fd, int type);
	
struct socket_server*
_server_create() {
	int r,i;
	
	struct socket_server *ss = malloc(sizeof(*ss));
	memset(ss, 0, sizeof(*ss));

	ss->efd = sp_create(MAX_EVENTS);
	if (ss->efd == -1) {
		perror("sp_create");
		exit(1);
	}

	int fd[2];
	r = pipe(fd);
	if (r == -1) {
		perror("pipe");
		exit(1);
	}

	ss->read_fd 	= fd[0];
	ss->write_fd 	= fd[1];

	r = sp_add(ss->efd, ss->read_fd, NULL);
	if (r == -1) {
		perror("sp_add");
		exit(1);
	}

	ss->ctrl_index  = 0;
	ss->ctrl_size   = 0;
	for (i = 0; i < MAX_EVENTS; i++) {
		struct event *e = &ss->ctrl_ev[i];
		e->s = NULL;
		e->is_write = 0;
		e->is_read  = 0;
	}

	ss->sk_use = 0;
	ss->sk_cap = MAX_EVENTS;
	ss->sk = malloc(sizeof(ss->sk) * ss->sk_cap);
	memset(ss->sk, 0, sizeof(ss->sk) * ss->sk_cap);

	r = pthread_mutex_init(&ss->cmd_lock, NULL);
	if (r != 0) {
		perror("pthread_mutex_init");
		exit(1);
	}
	
	return ss;
}


struct socket_msg_accept {
	int fd;
	struct sockaddr_in addr;
};

struct socket_msg_connect {

};

typedef union socket_msg {
	struct socket_msg_accept  accept_msg;
	struct socket_msg_connect connect_msg;
	struct socket_msg_data    data_msg;
} socket_msg_t;

struct socket_result {
	socket_msg_t data;
};

int 
set_nonblock(int fd) {
	int r,flags;  
	if ( (r = fcntl(fd, F_GETFL, 0)) < 0) {
    	perror("F_GETFL");  
		return r;
	}
	flags = r;
	flags |= O_NONBLOCK;  
	if ( (r = fcntl(fd, F_SETFL, flags)) < 0) {
    	perror("F_SETFL");  
		return r;
	}
	return r;
}

int
report_accept(struct socket_server *ss, int fd, struct socket_result *result) {
	int r;
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);
	r = accept(fd, (struct sockaddr*)&addr, &addr_len);
	if (r == -1) {
		if (errno == EAGAIN ||
			errno == EINTR) {
			return -1;	
		}
		perror("accept");
		exit(1);
	}

	printf("socket %d is connected\n", r);

	set_nonblock(r);

	result->data.accept_msg.fd   = r;
	result->data.accept_msg.addr = addr;

	_server_addfd(ss, r, SOCKET_TYPE_LISTEN);
	
	return SOCKET_MSG_ACCEPT;
}

int 
report_data(struct socket_server *ss, struct socket *s, struct socket_result *result) {
	int n, count = 0;
	char *msg = NULL;
	for (;;) {
		char buf[MAX_READ_SIZE];
		n = read(s->fd, buf, MAX_READ_SIZE);
		if (n < 0) {
			switch(errno) {
			case EAGAIN:
				{
					goto done;
				}break;
			case EINTR:
				{
					continue;
				}break;
			default:
				{
					perror("read");
					goto error;
				};
			}
		} else if (n == 0) {
			if (count != 0) {
				goto done;
			} else {
				goto error;
			}
		}
		msg = realloc(msg, count+n);
		memcpy(msg+count, buf, n);
		count += n;
	}

done:
	result->data.data_msg.id = s->id;
	result->data.data_msg.buf= msg;
	result->data.data_msg.buf_len = count;
	return SOCKET_MSG_DATA;

error:
	_server_delfd(ss, s);
	free(msg);
	return -1;
}

int 
has_cmd(int fd) {
	int n;
	fd_set rdset;
	FD_ZERO(&rdset);
	FD_SET(fd, &rdset);

	struct timeval tv;
	tv.tv_sec  = 0;
	tv.tv_usec = 0;

	n = select(fd+1, &rdset, NULL, NULL, &tv);
	if (n == 1) {
		return 1;
	}

	return 0;
}

struct socket_cmd_accept {
	int port;
};

#define HASH_ID(id) (id%ss->sk_cap)
int 
reserve_id(struct socket_server *ss) {
	return ss->atinc_id++;
};

struct socket *
_server_getsocket(struct socket_server *ss, int id) {
	struct socket *s = ss->sk[HASH_ID(id)];
	return s;
}

int
_server_addfd(struct socket_server *ss, int fd, int type) {
	int r;

	struct socket *s = malloc(sizeof(*s));
	memset(s, 0, sizeof(*s));

	r = sp_add(ss->efd, fd, s);
	if (r == -1) {
		free(s);
		return r;
	}

	
	if (ss->sk_use == ss->sk_cap) {
		ss->sk_cap *= 2;
		ss->sk = realloc(ss->sk, ss->sk_cap * sizeof(ss->sk));
		if (ss->sk == NULL) {
			perror("realloc");
			exit(1);
		}
		for (;;) {
			int id = reserve_id(ss);
			struct socket *os = ss->sk[HASH_ID(id)];
			if (os == NULL) {
				s->id   = id;
				s->fd   = fd;
				s->type = type;

				ss->sk[HASH_ID(id)] = s;
				ss->sk_use++;
				break;
			}
		}
	} else {
		for (;;) {
			int id = reserve_id(ss);
			struct socket *os = ss->sk[HASH_ID(id)];
			if (os == NULL) {
				s->id   = id;
				s->fd   = fd;
				s->type = type;

				ss->sk[HASH_ID(id)] = s;
				ss->sk_use++;
				break;
			}
		}
	}

	printf("epoll_add socket:%d\n", fd);

	return 0;
}

int
_server_delfd(struct socket_server *ss, struct socket *s) {
	assert(s);

	ss->sk[HASH_ID(s->id)] = NULL;
	ss->sk_use--;
	sp_del(ss->efd, s->fd);
	shutdown(s->fd, SHUT_RDWR);
	free(s->buf);
	free(s);

	return 0;
}

int
do_cmd_listen(struct socket_server *ss, struct socket_cmd_accept *cmd) {
	printf("do_cmd_listen port:%d\n", cmd->port);	

	int r, sockfd;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		perror("socket");
		exit(1);
	}
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(cmd->port);
	r = bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
	if (r == -1) {
		perror("bind");
		goto done;
	}

	set_nonblock(sockfd);

	r = listen(sockfd, 10);
	if (r == -1) {
		perror("listen");
		goto done;
	}
	r = _server_addfd(ss, sockfd, SOCKET_TYPE_ACCEPT);

done:
	free(cmd);
	return r;
}

struct socket_cmd_connect {
	int port;
	int ip_len;
	char *ip;
};

void connected_socket(struct socket_server *ss, int fd);


struct _connect_param {
	struct socket_server *ss;
	struct socket_cmd_connect *cmd;
};

void *
_connect(void *p) {
	int r,connfd;
	struct _connect_param *cp = (struct _connect_param*)p;
	struct socket_cmd_connect *cmd = cp->cmd;
	struct socket_server *ss  = cp->ss;

	connfd = socket(AF_INET, SOCK_STREAM, 0);
	if (connfd == -1) {
		perror("socket");
		exit(1);
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port   = htons(cmd->port);
	r = inet_pton(AF_INET, cmd->ip, &addr.sin_addr);
	if (r == 0) {
		printf("%s is not correct\n", cmd->ip);
		goto done;
	} else if (r < 0) {
		perror("inet_pton");
		goto done;
	}

	r = connect(connfd, (struct sockaddr*)&addr, sizeof(addr));
	if (r == -1) {
		perror("connect");
		goto done;
	}
	
	set_nonblock(connfd);
	
	connected_socket(ss, connfd);

done:
	free(cmd->ip);
	free(cmd);
	free(p);
	return NULL;
}

int 
do_cmd_connect(struct socket_server *ss, struct socket_cmd_connect *cmd) {
	printf("do_cmd_connect %s:%d\n", cmd->ip, cmd->port);

	struct _connect_param *p = malloc(sizeof(*p));
	p->ss  = ss;
	p->cmd = malloc(sizeof(*cmd));
	memcpy(p->cmd, cmd, sizeof(*cmd));
	p->cmd->ip  = malloc(cmd->ip_len);
	memcpy(p->cmd->ip, cmd->ip, cmd->ip_len);
	p->cmd->ip_len = cmd->ip_len;

	// start one pthread to connect 
	pthread_t pid;
	pthread_create(&pid, NULL, _connect, p);

	free(cmd->ip);
	free(cmd);
	return 0;
}

struct socket_cmd_connected {
	int fd;
};

int 
do_cmd_connected(struct socket_server *ss, struct socket_cmd_connected *cmd) {
	printf("do_cmd_connected %d\n", cmd->fd);

	_server_addfd(ss, cmd->fd, SOCKET_TYPE_CONNECT);

	free(cmd);
	return 0;
}


int 
write_msg(struct socket_server *ss, struct socket *s, char *msg, int msg_len) {
	if (s->buf_len)	{
		s->buf = realloc(s->buf, s->buf_len + msg_len);
		s->buf_len += msg_len;
		memcpy(s->buf+s->buf_len, msg, msg_len);
		return 0;
	}

	int n,count;
	count = 0;
	for (;;) {
		n = write(s->fd, msg+count, msg_len-count);
		if (n < 0) {
			switch (errno) {
			case EAGAIN:
				{
					s->buf = malloc(msg_len-count);					
					s->buf_len += msg_len-count;
					memcpy(s->buf, msg+count, msg_len-count);
					sp_write(ss->efd, s->fd, s);
					return 0;
				}break;
			case EINTR:
				{
					continue;
				}break;
			default:
				{
					perror("write");
					goto error;
				}break;
			}
		}

		count += n;
		if (count == msg_len) {
			return 0;
		}
	}

	return 0;

error:
	_server_delfd(ss, s);
	return -1;
}

int
write_appendbuffer(struct socket_server *ss, struct socket *s) {
	if (s->buf_len <= 0) {
		sp_unwrite(ss->efd, s->fd, s);
		return 0;
	}
	
	int n,count;
	count = 0;
	for (;;) {
		n = write(s->fd, s->buf+count, s->buf_len-count);
		if (n < 0) {
			switch(errno) {
			case EAGAIN:
				{
					memcpy(s->buf, s->buf+count, s->buf_len-count);
					s->buf = realloc(s->buf, s->buf_len-count);
					s->buf_len -= count;
					return 0;
				}break;
			case EINTR:
				{
					continue;
				}break;
			default:
				{
					perror("write");
					goto error;
				}break;
			}
		}
		count += n;
		if (count == s->buf_len) {
			sp_unwrite(ss->efd, s->fd, s);
			s->buf_len -= count; 	// must be 0
			free(s->buf);
			s->buf = NULL;
			return 0;
		}
	}
	return 0;

error:
	_server_delfd(ss, s);
	return -1;
}

struct socket_cmd_forward {
	int id; 	// to socket id
	int msg_len;
	char *msg;
};

int
do_cmd_forward(struct socket_server *ss, struct socket_cmd_forward *cmd) {
	int r;
	int id      = cmd->id;
	int msg_len = cmd->msg_len;
	char *msg   = cmd->msg;

	struct socket *s = _server_getsocket(ss, id);
	if (s == NULL) {
		r = 0;
		goto done;
	}

	r = write_msg(ss, s, msg, msg_len);

done:
	free(cmd->msg);
	free(cmd);
	return r;
}

struct socket_cmd_close {
	int id;
};

int 
do_cmd_close(struct socket_server *ss, struct socket_cmd_close *cmd) {
	printf("do_cmd_close id=%d\n", cmd->id);
	int r;
	int id = cmd->id;

	struct socket *s = _server_getsocket(ss, id);
	if (s == NULL) {
		goto done;
	}

	r = _server_delfd(ss, s);

done:
	free(cmd);
	return r;
}

int
block_read(int fd, void *buf, int size) {
	int n, count = 0;
	for (;;) {
		n = read(fd, buf+count, size-count);
		if (n < 0) {
			switch(errno) {
			case EINTR:
				{
					continue;
				}break;
			default:
				{
					perror("read pipe");
					exit(1);
				}break;
			}
		} else if (n == 0) {
			printf("read pipe n == 0\n");
			exit(1);
		} else {
			count += n;
			if (count == size) {
				break;
			}
		}
	}

	return 0;
}

int
ctl_cmd(struct socket_server *ss) {
	uint8_t type;
	block_read(ss->read_fd, &type, sizeof(type));

	void *cmd;
	block_read(ss->read_fd, &cmd, sizeof(cmd));

	switch(type) {
	case 'L':
		{
			do_cmd_listen(ss, cmd);
		}break;
	case 'P':
		{
			do_cmd_connect(ss, cmd);
		}break;
	case 'C':
		{
			do_cmd_connected(ss, cmd);
		}break;
	case 'F':
		{
			do_cmd_forward(ss, cmd);
		}break;
	case 'S':
		{
			do_cmd_close(ss, cmd);
		}break;
	}

	return -1;
}

int 
wait_msg(struct socket_server *ss, struct socket_result *result) {
	for (;;) {
		if (ss->check_cmd) {
			ss->check_cmd = 0;
			if (has_cmd(ss->read_fd)) {
				ctl_cmd(ss);
				continue;
			}
		}
		if (ss->ctrl_index == ss->ctrl_size) {
			ss->ctrl_index = 0;
			ss->ctrl_size  = sp_wait(ss->efd, ss->ctrl_ev, MAX_EVENTS);
			if (ss->ctrl_size == -1) {
				switch(errno) {
				case EINTR:
					ss->ctrl_size = 0;
					continue;
				default:
					{
						perror("sp_wait");
						exit(1);
					}break;
				}
			}
		}
		ss->check_cmd = 1;
		
		struct event *e = &ss->ctrl_ev[ss->ctrl_index++];
		struct socket *s = e->s;
		if (NULL == s) {
			continue;
		}
		switch(s->type) {
		case SOCKET_TYPE_ACCEPT:
			{
				return report_accept(ss, s->fd, result);	
			}break;
		default:
			{
				if (e->is_write) {
					write_appendbuffer(ss, s);
				}
				if (e->is_read) {
					return report_data(ss, s, result);					
				}
			}break;
		}
	}
}

//-------------------------------The Interface---------------------------------

struct socket_server*
socket_server_create(msg_func f) {
	struct socket_server *ss = _server_create();	
	ss->msg_push = f;
	return ss;
}

void 
socket_server_poll(struct socket_server *ss) {
	int t;
	for (;;) {
		struct socket_result result;
		t = wait_msg(ss, &result);
		switch(t) {
		case SOCKET_MSG_DATA:
			{
				ss->msg_push(&result.data.data_msg);
			}break;
		case SOCKET_MSG_ACCEPT:
			{
			};
		default:
			{
				continue;
			};
		}
	}
}

void
listen_socket(struct socket_server *ss, int port) {
	uint8_t d = 'L';
	struct socket_cmd_accept *cmd = malloc(sizeof(*cmd));
	cmd->port = port;	

	pthread_mutex_lock(&ss->cmd_lock);
	write(ss->write_fd, &d, sizeof(d));
	write(ss->write_fd, &cmd, sizeof(cmd));
	pthread_mutex_unlock(&ss->cmd_lock);
}

void
connect_socket(struct socket_server *ss, char *ip, int ip_len, int port) {
	uint8_t d = 'P';
	struct socket_cmd_connect *cmd = malloc(sizeof(*cmd));
	cmd->ip 	= malloc(ip_len);
	memcpy(cmd->ip, ip, ip_len);
	cmd->ip_len = ip_len;
	cmd->port 	= port;

	pthread_mutex_lock(&ss->cmd_lock);
	write(ss->write_fd, &d, sizeof(d));
	write(ss->write_fd, &cmd, sizeof(cmd));
	pthread_mutex_unlock(&ss->cmd_lock);
}

void 
connected_socket(struct socket_server *ss, int fd) {
	uint8_t d = 'C';
	struct socket_cmd_connected *cmd = malloc(sizeof(*cmd));
	cmd->fd = fd;
	
	pthread_mutex_lock(&ss->cmd_lock);
	write(ss->write_fd, &d, sizeof(d));
	write(ss->write_fd, &cmd, sizeof(cmd));
	pthread_mutex_unlock(&ss->cmd_lock);
}

void 
write_socket(socket_server *ss, int id, char *msg, int msg_len) {
	uint8_t d = 'F';
	struct socket_cmd_forward *cmd = malloc(sizeof(*cmd));
	cmd->id  = id;
	cmd->msg = malloc(msg_len);
	memcpy(cmd->msg, msg, msg_len);
	cmd->msg_len = msg_len;

	pthread_mutex_lock(&ss->cmd_lock);
	write(ss->write_fd, &d, sizeof(d));
	write(ss->write_fd, &cmd, sizeof(cmd));
	pthread_mutex_unlock(&ss->cmd_lock);
}

void
close_socket(socket_server *ss, int id) {
	uint8_t d = 'S';
	struct socket_cmd_close *cmd = malloc(sizeof(*cmd));
	cmd->id = id;

	pthread_mutex_lock(&ss->cmd_lock);
	write(ss->write_fd, &d, sizeof(d));
	write(ss->write_fd, &cmd, sizeof(cmd));
	pthread_mutex_unlock(&ss->cmd_lock);
}
