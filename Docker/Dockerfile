FROM ubuntu:22.04

RUN apt-get update && apt-get install -y     build-essential     clang     llvm     libelf-dev     linux-headers-generic     git     cmake     libseccomp-dev     && rm -rf /var/lib/apt/lists/*

WORKDIR /app
