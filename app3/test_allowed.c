// test_allowed.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    printf("Testing allowed syscalls\n");
    
    // Test allowed read/write
    char buffer[128];
    write(STDOUT_FILENO, "Hello, World!\n", 14);
    
    // Open a file (should work if allowed)
    int fd = open("/tmp/test.txt", O_CREAT | O_WRONLY, 0644);
    if (fd != -1) {
        printf("Successfully opened file\n");
        close(fd);
    } else {
        perror("Failed to open file");
    }
    
    return 0;
}

