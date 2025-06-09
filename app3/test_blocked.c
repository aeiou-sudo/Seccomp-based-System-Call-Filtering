// test_blocked.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main() {
    printf("Testing blocked syscalls\n");
    
    // Try to create a socket (block this in your policy)
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    
    // This should not be reached if socket is blocked
    if (sock != -1) {
        printf("Socket created (not blocked by filter)\n");
        close(sock);
    } else {
        perror("Failed to create socket");
    }
    
    return 0;
}
