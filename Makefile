all : server client client2

server : main.c net_socket.c net_poll.c
	gcc -g -Wall -o $@ $^ -lpthread

client : client.c
	gcc -g -Wall -o $@ $^

client2 : client2.c
	gcc -g -Wall -o $@ $^

clean :
	rm server client client2
