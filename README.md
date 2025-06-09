# Seccomp-Based System Call Filtering

This project implements a secure, policy-driven system call (syscall) filtering mechanism using the Linux **seccomp** framework and the **libseccomp** library. It aims to enhance application security by restricting the set of allowed system calls based on user-defined rules — either completely blocking specific syscalls or applying argument-based filtering.

## 🔐 Motivation

Modern applications often invoke unnecessary or risky system calls, which can be exploited for privilege escalation, data exfiltration, or other attacks. Traditional Linux security tools like SELinux and AppArmor lack the fine-grained syscall control that **seccomp** offers. This project demonstrates how seccomp can be effectively used to sandbox applications, especially in environments like:

- Containerized runtimes (e.g., Docker, Kubernetes)
- Embedded and IoT systems
- Security-sensitive user space programs

## 🎯 Objectives

- Implement syscall filtering using `libseccomp` with both **basic** and **advanced (argument-based)** policies
- Validate security enforcement through **test programs** and **debug mode**
- Demonstrate real-world utility by restricting operations like network socket creation or file access

## 🏗️ Architecture Overview

The system is composed of four layers:

1. **Policy Layer**: Defines syscall restrictions in plain text files
2. **Filter Layer**: Implements filtering logic via two programs:
   - `syscall_filter.c` for basic filtering
   - `syscall_filter_advanced.c` for argument-based filtering
3. **Application Layer**: Sample test programs to demonstrate allowed and blocked syscalls
4. **Automation Layer**: `demo.sh` script to compile and run demo scenarios automatically

## 📁 Repository Structure

```
├── syscall_filter.c           # Basic syscall filter
├── syscall_filter_advanced.c  # Advanced filter with argument checks
├── test_allowed.c             # Executes allowed syscalls
├── test_blocked.c             # Executes blocked syscalls
├── demo.sh                    # Demo runner script
├── basic_policy.txt           # Blocks basic socket-related syscalls
├── restrictive_policy.txt     # More restrictive variant of basic policy
├── advanced_policy.txt        # Includes argument-based blocking
└── README.md                  # This file
```

## 🚀 Getting Started

### 🛠️ Prerequisites

- GCC (with seccomp support)
- libseccomp ≥ v2.5.0
- Linux kernel with seccomp support

```bash
# Ubuntu/Debian
sudo apt-get install libseccomp-dev

# CentOS/RHEL/Fedora
sudo yum install libseccomp-devel
# or
sudo dnf install libseccomp-devel
```

### 🧪 Build and Run Demo

```bash
chmod +x demo.sh
./demo.sh
```

This will:
- Generate the policy files
- Compile all programs
- Run demonstrations showing basic and advanced syscall blocking
- Enable debug output if specified

## 🧩 Key Features

- **Basic Policy Filtering**: Blocks high-risk syscalls such as `socket()`, `connect()`, etc.
- **Advanced Filtering**: Blocks syscalls only when invoked with specific argument values (e.g., block `open()` with `O_RDWR`)
- **Debug Mode**: Verbose logging of each blocked syscall for inspection
- **Portable Policies**: Easily extensible `.txt` files for defining custom rules

## 📊 Sample Output

### Basic Filtering

| Test Program   | Policy                 | Outcome                                    |
|----------------|------------------------|--------------------------------------------|
| test_allowed   | basic_policy.txt       | ✅ Success — file I/O allowed             |
| test_blocked   | restrictive_policy.txt | ❌ Failure — terminated on `socket()`     |

### Advanced Filtering

- `open()` with `O_WRONLY` → ✅ Allowed
- `open()` with `O_RDWR` → ❌ Blocked

## 🐛 Debug Mode Example

```bash
./syscall_filter_advanced -t advanced_policy.txt ./test_allowed
```

Output:
```
[DEBUG] Blocking syscall: socket
[DEBUG] Blocking open with arg1=2
Seccomp filter loaded successfully
```

## 🧱 Challenges Addressed

- **Compatibility with outdated libseccomp**: Resolved by replacing tracing features with debug logging
- **Argument parsing robustness**: Enhanced by validating argument numbers and values
- **Cross-platform compatibility**: Ensured compatibility across different Linux distributions

## 🔧 Usage Examples

### Basic Usage

```bash
# Compile the basic filter
gcc -o syscall_filter syscall_filter.c -lseccomp

# Run with a policy file
./syscall_filter basic_policy.txt ./your_program
```

### Advanced Usage with Argument Filtering

```bash
# Compile the advanced filter
gcc -o syscall_filter_advanced syscall_filter_advanced.c -lseccomp

# Run with debug mode
./syscall_filter_advanced -t advanced_policy.txt ./your_program
```

## 📝 Policy File Format

### Basic Policy
```
socket
connect
bind
listen
```

### Advanced Policy
```
socket
open:1:2    # Block open() when arg1 equals 2
write:0:1   # Block write() when arg0 equals 1
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## 📌 Conclusion

This project demonstrates the effective use of seccomp and libseccomp for building lightweight yet powerful syscall sandboxes. It is a practical starting point for integrating syscall filtering into:

- Container security
- Runtime hardening
- Embedded device safety enforcement

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Paul Jose**  
M.Tech in Computer Science and Engineering  
Mar Athanasius College of Engineering, Kerala

## 🙏 Acknowledgments

- Linux seccomp framework developers
- libseccomp library maintainers
- Open source security community

---

*For questions or support, please open an issue in this repository.*
