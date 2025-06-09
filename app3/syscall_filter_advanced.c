#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <seccomp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

void setup_advanced_filter(char *policy_file, int debug_mode) {
    scmp_filter_ctx ctx;
    FILE *fp;
    char line[256];
    char syscall_name[64];
    char arg_spec[128];
    int action, arg_num;
    unsigned long arg_val;
    
    // Initialize with default allow action
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL) {
        fprintf(stderr, "Failed to initialize seccomp filter\n");
        exit(1);
    }
    
    fp = fopen(policy_file, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open policy file: %s\n", policy_file);
        seccomp_release(ctx);
        exit(1);
    }
    
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n')
            line[len-1] = '\0';
            
        if (line[0] == '#' || line[0] == '\0')
            continue;
        
        arg_spec[0] = '\0';
        if (sscanf(line, "%d %63s %127s", &action, syscall_name, arg_spec) >= 2) {
            int syscall_num = seccomp_syscall_resolve_name(syscall_name);
            if (syscall_num == __NR_SCMP_ERROR) {
                fprintf(stderr, "Unknown syscall: %s\n", syscall_name);
                continue;
            }
            
            if (action == 0) {
                if (arg_spec[0] == '\0') {
                    if (debug_mode) {
                        printf("[DEBUG] Blocking syscall: %s\n", syscall_name);
                    }
                    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, syscall_num, 0) < 0) {
                        fprintf(stderr, "Failed to add block rule for %s\n", syscall_name);
                    }
                } else {
                    if (sscanf(arg_spec, "arg%d=%lu", &arg_num, &arg_val) != 2) {
                        fprintf(stderr, "Invalid argument spec: %s\n", arg_spec);
                        continue;
                    }
                    
                    if (arg_num < 0 || arg_num > 5) {
                        fprintf(stderr, "Invalid arg number: %d\n", arg_num);
                        continue;
                    }
                    
                    if (debug_mode) {
                        printf("[DEBUG] Blocking %s with arg%d=%lu\n", syscall_name, arg_num, arg_val);
                    }
                    int result = seccomp_rule_add(ctx, SCMP_ACT_KILL, syscall_num, 1,
                                 SCMP_CMP(arg_num, SCMP_CMP_EQ, arg_val));
                    if (result < 0) {
                        fprintf(stderr, "Failed to add rule for %s\n", syscall_name);
                    }
                }
            }
        } else {
            fprintf(stderr, "Invalid rule: %s\n", line);
        }
    }
    
    fclose(fp);
    
    if (seccomp_load(ctx) < 0) {
        fprintf(stderr, "Failed to load filter: %s\n", strerror(errno));
        seccomp_release(ctx);
        exit(1);
    }
    
    seccomp_release(ctx);
    printf("Seccomp filter loaded successfully\n");
}

int main(int argc, char *argv[]) {
    int debug_mode = 0;
    char *policy_file;
    char **cmd_args;
    
    if (argc < 3) {
        fprintf(stderr, "Usage: %s [-t] <policy_file> <command> [args...]\n", argv[0]);
        exit(1);
    }
    
    if (strcmp(argv[1], "-t") == 0) {
        debug_mode = 1;
        policy_file = argv[2];
        cmd_args = &argv[3];
    } else {
        policy_file = argv[1];
        cmd_args = &argv[2];
    }
    
    printf("Setting up advanced syscall filter with policy: %s\n", policy_file);
    setup_advanced_filter(policy_file, debug_mode);
    
    execvp(cmd_args[0], cmd_args);
    perror("execvp failed");
    return 1;
}
