#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int 
main(void) {
	int r, sockfd;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("socket");
		exit(1);
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port   = htons(8011);
	inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

	r = connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));
	if (r == -1) {
		perror("connect");
		exit(1);
	}

	char buf[20];
	snprintf(buf, sizeof(buf), "%s", "welcome you");
	r = write(sockfd, buf, sizeof(buf));
	printf("write fd=%d r=%d\n", sockfd, r);

	memset(buf, 0, sizeof(buf));
	r = read(sockfd, buf, sizeof(buf));
	printf("read:%s from fd=%d\n", buf, sockfd);

	return 0;
}

