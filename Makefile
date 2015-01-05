all : server client

server : main.c net_socket.c net_poll.c
	gcc -g -Wall -o $@ $^ -lpthread

client : client.c
	gcc -g -Wall -o $@ $^

clean :
	rm server client
