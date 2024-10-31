FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y iproute2 iputils-ping && \
    rm -rf /var/lib/apt/lists/*

# Set default command to keep container running
CMD ["sleep", "infinity"]