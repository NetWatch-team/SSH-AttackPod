# Stage 1: Build stage
FROM ubuntu:24.04 AS builder

# Set environment variable for non-interactive installations
ENV DEBIAN_FRONTEND=noninteractive

# Enable 'deb-src' entries dynamically for all architectures and install dependencies
RUN sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null || true && \
    apt-get update && \
    apt-get install --no-install-recommends -y \
    build-essential \
    fakeroot \
    devscripts \
    tzdata \
    openssh-client \
    putty-tools \
    python3-twisted && \
    apt-get build-dep --no-install-recommends -y openssh-server && \
    mkdir -p /src && cd /src && \
    apt-get source openssh-server && \
    cd openssh-* && \
    sed -i 's/^\([ \t]*\)\(struct passwd \*pw = authctxt->pw;\)/\1logit("Login attempt by username '\''%s'\'', password '\''%s'\'', from ip '\''%.200s'\''", authctxt->user, password, ssh_remote_ipaddr(ssh));\nreturn 0;\1\2/' auth-passwd.c && \
    debchange --nmu 'add verbose logging of usernames and passwords' && \
    EDITOR=true dpkg-source --commit . 'chatty-ssh.patch' && \
    debuild -us -uc -i -I && \
    apt-get clean && apt-get autoremove -y

# Stage 2: Runtime stage
FROM ubuntu:24.04

# Set environment variable for non-interactive installations
ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies only
RUN apt-get update && \
    apt-get install --no-install-recommends -y \
    python3-pip \
    python3-venv \
    openssh-server && \
    apt-get clean && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Copy patched sshd binary and configuration from builder stage
COPY --from=builder /src/openssh-*/debian/tmp/usr/sbin/sshd /usr/sbin/sshd

# Create a non-root user
RUN groupadd -r appuser && useradd -r -g appuser -m appuser

# Move sshd to Port 2222 and prepare directories for non-root execution
RUN sed -i.orig -e 's/^#\(Port 22\)/\122/' /etc/ssh/sshd_config && \
    mkdir -p /etc/ssh /etc/ssh/host_keys /run/sshd /var/lib/netwatch_gateway && \
    chmod 0755 /run/sshd && \
    touch /var/log/ssh.log && \
    chown -R appuser:appuser /etc/ssh /var/log/ssh.log /var/lib/netwatch_gateway

# Set working directory
WORKDIR /home/appuser/code
RUN chown -R appuser:appuser /home/appuser

# Switch to appuser to install virtualenv dependencies and run unprivileged
USER appuser
COPY --chown=appuser:appuser requirements.txt /home/appuser/code/

# Create virtual environment and install dependencies
RUN python3 -m venv /home/appuser/venv && \
    /home/appuser/venv/bin/pip install --no-cache-dir -r requirements.txt

# Use venv Python and pip as default
ENV PATH="/home/appuser/venv/bin:$PATH"
ENV SSH_LISTEN_PORT=2222

# Copy application code (including Gateway and Sequence Admission Engine)
COPY --chown=appuser:appuser monitor.py gateway.py admission_engine.py /home/appuser/code/

# Expose 2222
EXPOSE 2222

# Report the version of the openSSH server
RUN /usr/sbin/sshd -V || true

# Healthcheck probing SSH listener port
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python3 -c "import os, socket; s = socket.create_connection(('127.0.0.1', int(os.getenv('SSH_LISTEN_PORT', '2222'))), timeout=3); s.close()"

# Command to run application
CMD ["python3", "monitor.py"]
