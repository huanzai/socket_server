#include "net_socket.h"

#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

struct _mq {
	int msg_type;
	void*msg;
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
		switch(q->msg_type) {
		case SOCKET_MSG_DATA:
			{
				struct socket_msg_data *msg = q->msg;
				{
					printf("data_id\t\t:%d\n", msg->id);
					printf("data_buf\t:%s\n", msg->buf);
					printf("data_buf_len\t:%d\n", msg->buf_len);
				}

				if (!strncmp(msg->buf, "close", msg->buf_len)) {
					close_socket(ss, msg->id);
				} else {
					write_socket(ss, msg->id, "Iam HuanZai", sizeof("Iam HuanZai"));
				}
				
				free(msg->buf);
				free(msg);
			}break;
		case SOCKET_MSG_ACCEPT:
			{
				struct socket_msg_accept *accept = q->msg;
				{
					printf("accept_id\t:%d\n", accept->id);
					char addr[1024]={0};
					inet_ntop(AF_INET, &accept->addr.sin_addr, addr, sizeof(addr));
					printf("accept_addr\t:%s:%d\n", addr, ntohs(accept->addr.sin_port));
				}

				free(accept);
			}break;
		case SOCKET_MSG_CONNECT:
			{
				struct socket_msg_connect *connect = q->msg;
				{
					printf("connect_id:%d\n", connect->id);
				}

				free(connect);
			}break;
		case SOCKET_MSG_CLOSE:
			{
				struct socket_msg_close *close = q->msg;
				{
					printf("close_id:%d\n", close->id);
				}

				free(close);
			}break;
		}
		
		pthread_mutex_unlock(&lock);
	}
	return NULL;
}

void recv_msg(int type, void*msg, int msg_len) {
	void *nmsg = malloc(msg_len);
	memcpy(nmsg, msg, msg_len);

	struct _mq *q = malloc(sizeof(*q));
	q->msg = nmsg;
	q->msg_type = type;
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
