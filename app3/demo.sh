#!/bin/bash
# demo.sh

# First, create the required policy files

# Basic policy for test_allowed - only block socket operations
cat > basic_policy.txt << 'EOL'
# Basic policy file - block socket operations
# Format: action syscall_name
# action: 0 = block, 1 = allow (default is allow)
0 socket
0 connect
0 bind
0 listen
0 accept
0 accept4
EOL

# Restrictive policy for test_blocked
cat > restrictive_policy.txt << 'EOL'
# Restrictive policy file
# Format: action syscall_name
# action: 0 = block, 1 = allow (default is allow)
0 socket
0 connect
0 bind
0 listen
0 accept
0 accept4
EOL

# Advanced policy
cat > advanced_policy.txt << 'EOL'
# Advanced policy file
# Format: action syscall_name [arg specification]
# action: 0 = block, 1 = allow (default is allow)

# Block socket operations
0 socket
0 connect
0 bind
0 listen
0 accept
0 accept4

# Example of argument-specific blocking
# Block open with specific flags
# This blocks open() when O_RDWR (2) is used
0 open arg1=2
EOL

echo "Compiling syscall filter..."
gcc -o syscall_filter syscall_filter.c -lseccomp
gcc -o syscall_filter_advanced syscall_filter_advanced.c -lseccomp

echo "Compiling test programs..."
gcc -o test_allowed test_allowed.c
gcc -o test_blocked test_blocked.c

echo -e "\n--- Basic filtering demo ---"
echo "Running test_allowed with permissive policy:"
./syscall_filter basic_policy.txt ./test_allowed

echo -e "\nRunning test_blocked with restrictive policy:"
./syscall_filter restrictive_policy.txt ./test_blocked

echo -e "\n--- Advanced filtering demo ---"
echo "Running with argument-based filtering:"
./syscall_filter_advanced advanced_policy.txt ./test_allowed

echo -e "\n--- Debug mode ---"
echo "Running with debug prints:"
./syscall_filter_advanced -t advanced_policy.txt ./test_allowed
