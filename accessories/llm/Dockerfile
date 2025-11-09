# Base image
FROM alpine:3.22

# System dependencies
RUN apk add --no-cache \
    bash \
    git \
    build-base \
    cmake \
    wget \
    curl-dev \
    curl \
    unzip \
    pkgconfig \
    musl-dev \
    python3 \
    py3-virtualenv \
    libffi-dev \
    openssl-dev

# Clone and build llama.cpp
RUN git clone --depth 1 https://github.com/ggerganov/llama.cpp.git /opt/llama.cpp && \
    cd /opt/llama.cpp && \
    mkdir -p build && cd build && \
    cmake .. && \
    make -j$(nproc)

# Create models directory and download model
RUN mkdir -p /opt/models && \
    curl -L -o /opt/models/Llama-3.2-3B-Instruct-Q4_K_M.gguf \
    https://huggingface.co/tensorblock/Llama-3.2-3B-Instruct-GGUF/resolve/main/Llama-3.2-3B-Instruct-Q4_K_M.gguf

RUN mkdir -p /opt/models && \
    curl -L -o /opt/models/SmolLM3-3B-GGUF.gguf \
    https://huggingface.co/ggml-org/SmolLM3-3B-GGUF/resolve/main/SmolLM3-Q4_K_M.gguf

# Expose API port
EXPOSE 5555

# Run llama-server directly
CMD ["/opt/llama.cpp/build/bin/llama-server", "--model", "/opt/models/Llama-3.2-3B-Instruct-Q4_K_M.gguf", "--host", "0.0.0.0", "--port", "5555", "--threads", "3", "--no-webui"]
#CMD ["/opt/llama.cpp/build/bin/llama-server", "--model", "/opt/models/SmolLM3-3B-GGUF.gguf", "--host", "0.0.0.0", "--port", "5555", "--threads", "3", "--no-webui"]
