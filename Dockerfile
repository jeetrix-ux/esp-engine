# Dev/test image: native toolchain, sanitizers, QEMU user-mode for cross-arch runs,
# iproute2 for the netns + kernel XFRM interop tests.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential clang libclang-rt-14-dev make perl python3 python3-pytest python3-scapy \
      python3-cryptography iproute2 iputils-ping tcpdump \
      gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
      gcc-riscv64-linux-gnu libc6-dev-riscv64-cross \
      qemu-user \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
