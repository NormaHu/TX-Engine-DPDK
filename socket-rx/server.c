#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#define BUF_SIZE 2000

void error(const char *msg)
{
	    perror(msg);
		    exit(0);
}


int main(int argc, char *argv[])
{
	int server_sockfd;
	int len, sid;
	struct sockaddr_in server;
	struct sockaddr_in client;
	int server_size, client_size;
	char buf[BUF_SIZE];

	server_size = sizeof(struct sockaddr_in);

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	//server.sin_addr.s_addr = inet_addr("1.1.2.3");
	server.sin_port = htons(55117);

	sid = socket(AF_INET, SOCK_DGRAM, 0);
	if (sid < 0) {
		printf("create socket error\n");
		exit(1);
	}
	if (bind(sid, (struct sockaddr *)&server, server_size) < 0) {
		printf("bind fail\n");
		exit(1);
	}
	
	printf("waiting for a packet......\n");
	
	/* We can't re-use server_size here! must use a new variant */
	client_size = sizeof(struct sockaddr_in);
	while (1) {
		len = recvfrom(sid, buf, BUF_SIZE, 0, (struct sockaddr *)&client, &client_size);
		if (len < 0) {
			error("recvfrom fail");
			exit(1);
		}

		printf("receiving packet from %s\n", inet_ntoa(client.sin_addr));
		buf[len] = '\0';
		printf("len:%d\ncontent:%s\n\n", len, buf);
	}
	return 0;
}
