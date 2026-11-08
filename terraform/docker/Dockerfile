# Stage 1: Build stage
FROM ubuntu:24.04 AS builder

# Set environment variable for non-interactive installations
ENV DEBIAN_FRONTEND=noninteractive

# Enable 'deb-src' entries dynamically for all architectures, install build dependencies, and compile patched OpenSSH
# hadolint ignore=DL3008,DL3009,DL3003
RUN sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null || true && \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get install --no-install-recommends -y \
        build-essential \
        fakeroot \
        devscripts \
        tzdata \
        openssh-client \
        putty-tools \
        python3-twisted \
        python3-pip \
        python3-venv && \
    apt-get build-dep --no-install-recommends -y openssh-server && \
    mkdir -p /src && cd /src && \
    apt-get source openssh-server && \
    cd openssh-* && \
    sed -i 's/^\([ \t]*\)\(struct passwd \*pw = authctxt->pw;\)/\1logit("Login attempt by username '\''%s'\'', password '\''%s'\'', from ip '\''%.200s'\''", authctxt->user, password, ssh_remote_ipaddr(ssh));\nreturn 0;\1\2/' auth-passwd.c && \
    debchange --nmu 'add verbose logging of usernames and passwords' && \
    EDITOR=true dpkg-source --commit . 'chatty-ssh.patch' && \
    debuild -us -uc -i -I && \
    apt-get clean && apt-get autoremove -y

# Build isolated Python virtual environment in builder stage to omit pip/build tools from runtime
COPY requirements.txt /tmp/requirements.txt
# hadolint ignore=DL3013
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel && \
    /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt && \
    /opt/venv/bin/pip uninstall -y pip setuptools wheel || true && \
    rm -rf /opt/venv/bin/pip* /opt/venv/bin/easy_install* && \
    find /opt/venv -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

# Stage 2: Sleek, hardened runtime stage
FROM ubuntu:24.04

# Set environment variable for non-interactive installations
ENV DEBIAN_FRONTEND=noninteractive

# Apply security upgrades and install only required runtime dependencies (no pip, no compiler tools)
# hadolint ignore=DL3008,DL3009
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install --no-install-recommends -y \
        python3 \
        openssh-server && \
    apt-get clean && \
    apt-get autoremove -y && \
    rm -rf /etc/ssh/ssh_host_* /var/lib/apt/lists/* /tmp/* /var/tmp/* /usr/share/doc/* /usr/share/man/*

# Copy patched sshd binary from builder stage
COPY --from=builder /src/openssh-*/debian/tmp/usr/sbin/sshd /usr/sbin/sshd

# Copy isolated, hardened Python virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv

# Create a non-root system user
RUN groupadd -r appuser && useradd -r -g appuser -m -d /home/appuser -s /bin/bash appuser

# Move sshd to Port 2222, prepare runtime directories, and ensure no default host keys remain baked in
RUN sed -i.orig -e 's/^#\(Port 22\)/\122/' /etc/ssh/sshd_config && \
    mkdir -p /etc/ssh /etc/ssh/host_keys /run/sshd /var/lib/netwatch_gateway /var/log && \
    chmod 0755 /run/sshd && \
    touch /var/log/ssh.log && \
    rm -f /etc/ssh/ssh_host_* && \
    chown -R appuser:appuser /etc/ssh /var/log/ssh.log /var/lib/netwatch_gateway /opt/venv

# Set working directory
WORKDIR /home/appuser/code
RUN chown -R appuser:appuser /home/appuser

# Switch to appuser to run completely unprivileged
USER appuser

# Default PATH and environment variables
ENV PATH="/opt/venv/bin:$PATH"
ENV SSH_LISTEN_PORT=2222

# Copy application code
COPY --chown=appuser:appuser monitor.py gateway.py admission_engine.py /home/appuser/code/

# Expose SSH port
EXPOSE 2222

# Report the version of the OpenSSH server and ensure host keys were not generated
RUN /usr/sbin/sshd -V || true

# Healthcheck probing SSH listener port
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python3 -c "import os, socket; s = socket.create_connection(('127.0.0.1', int(os.getenv('SSH_LISTEN_PORT', '2222'))), timeout=3); s.close()"

# Command to run application
CMD ["python3", "monitor.py"]
