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

# Adjust permissions for SSH, run directory and log files
RUN mkdir -p /etc/ssh /run/sshd && \
    chmod 0755 /run/sshd && \
    touch /var/log/ssh.log

# Set working directory
WORKDIR /home/appuser/code
RUN chown -R appuser:appuser /home/appuser

# Switch to appuser to install virtualenv dependencies
USER appuser
COPY requirements.txt /home/appuser/code/

# Create virtual environment and install dependencies
RUN python3 -m venv /home/appuser/venv && \
    /home/appuser/venv/bin/pip install --no-cache-dir -r requirements.txt

# Use venv Python and pip as default
ENV PATH="/home/appuser/venv/bin:$PATH"

# Copy application code
COPY monitor.py /home/appuser/code/

# Switch back to root for system configuration and execution
USER root

# Move sshd to Port 2222
# change /etc/ssh/sshd_config by uncommenting Port 22 and changing it to Port 2222
RUN sed -i.orig -e 's/^#\(Port 22\)/\122/' /etc/ssh/sshd_config

# Expose 2222
EXPOSE 2222

# Report the version of the openSSH server
RUN sshd -V

# Command to run your application
CMD ["python3", "monitor.py"]

