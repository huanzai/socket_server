#include "net_socket.h"

#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

struct _mq {
	struct socket_msg_data *msg;
	struct _mq* next;
};

struct global_mq {
	struct _mq *msg;
};

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
struct global_mq g_mq;

void* 
_socket(void *p) {
	socket_server *ss = (socket_server *)p;
	socket_server_poll(ss);
	return NULL;
}

void* 
_worker(void *p) {
	socket_server *ss = (socket_server *)p;
	for (;;) {
		pthread_mutex_lock(&lock);
		if (!g_mq.msg) {
			pthread_cond_wait(&cond, &lock);
		}
		struct _mq *q = g_mq.msg;
		g_mq.msg = q->next;

		// deal msg
		struct socket_msg_data *msg = q->msg;
		if (!strncmp(msg->buf, "close", msg->buf_len)) {
			close_socket(ss, msg->id);
		} else {
			write_socket(ss, msg->id, "Iam HuanZai", sizeof("Iam HuanZai"));
		}
		
		pthread_mutex_unlock(&lock);
	}
	return NULL;
}

void recv_msg(struct socket_msg_data *msg) {
	printf("msg.id=%d\n", msg->id);
	printf("msg.buf=%s\n", msg->buf);
	printf("msg.len=%d\n", msg->buf_len);

	struct socket_msg_data *nmsg = malloc(sizeof(*nmsg));
	memcpy(nmsg, msg, sizeof(*nmsg));
	nmsg->buf = malloc(msg->buf_len);
	memcpy(nmsg->buf, msg->buf, msg->buf_len);
	nmsg->buf_len = msg->buf_len;

	struct _mq *q = malloc(sizeof(*q));
	q->msg = nmsg;
	q->next= NULL;
	
	pthread_mutex_lock(&lock);
	{
		if (!g_mq.msg) {
			g_mq.msg = q;
		} else {
			struct _mq *tq = g_mq.msg;
			for (;;) {
				if (tq->next == NULL) {
					tq->next = q;
					break;
				} else {
					tq = tq->next;
				}
			}
		}
	}	
	pthread_cond_broadcast(&cond);
	pthread_mutex_unlock(&lock);
}

int 
main(void) {
	int i;
	pthread_t pid[2];

	socket_server *ss = socket_server_create(recv_msg);

	pthread_create(&pid[0], NULL, _socket, ss);
	pthread_create(&pid[1], NULL, _worker, ss);

	listen_socket(ss, 8011);
	connect_socket(ss, "127.0.0.1", sizeof("127.0.0.1"), 8012);

	for (i = 0; i < 2; i++) {
		pthread_join(pid[i], NULL);
	}

	return 0;
}
