// syscall_filter.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <seccomp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

void setup_seccomp_filter(char *policy_file) {
    scmp_filter_ctx ctx;
    FILE *fp;
    char line[256];
    char syscall_name[64];
    int action;
    
    // Initialize the seccomp filter context with default allow policy
    // (We'll explicitly block specific syscalls instead)
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL) {
        fprintf(stderr, "Failed to initialize seccomp filter\n");
        exit(1);
    }
    
    // Read policy file
    fp = fopen(policy_file, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open policy file: %s\n", policy_file);
        seccomp_release(ctx);
        exit(1);
    }
    
    // Parse policy file
    while (fgets(line, sizeof(line), fp)) {
        // Remove newline if present
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n')
            line[len-1] = '\0';
            
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\0')
            continue;
        
        // Parse line: format is "0/1 syscall_name"
        if (sscanf(line, "%d %63s", &action, syscall_name) == 2) {
            int syscall_num = seccomp_syscall_resolve_name(syscall_name);
            if (syscall_num == __NR_SCMP_ERROR) {
                fprintf(stderr, "Unknown syscall: %s\n", syscall_name);
                continue;
            }
            
            // Add rule to filter
            if (action == 0) { // block
                printf("Blocking syscall: %s\n", syscall_name);
                if (seccomp_rule_add(ctx, SCMP_ACT_KILL, syscall_num, 0) < 0) {
                    fprintf(stderr, "Failed to add block rule for %s\n", syscall_name);
                }
            }
            // For allow (1), we don't need to do anything as the default action is ALLOW
        }
    }
    
    fclose(fp);
    
    // Load the filter into the kernel
    if (seccomp_load(ctx) < 0) {
        fprintf(stderr, "Failed to load seccomp filter: %s\n", strerror(errno));
        seccomp_release(ctx);
        exit(1);
    }
    
    printf("Seccomp filter loaded successfully\n");
    seccomp_release(ctx);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <policy_file> <command> [args...]\n", argv[0]);
        exit(1);
    }
    
    char *policy_file = argv[1];
    
    printf("Setting up syscall filter with policy: %s\n", policy_file);
    setup_seccomp_filter(policy_file);
    
    printf("Executing command: %s\n", argv[2]);
    
    // Use execvp instead of system()
    char **cmd_args = &argv[2];
    execvp(cmd_args[0], cmd_args);
    
    // If we reach here, exec failed
    perror("execvp failed");
    return 1;
}

