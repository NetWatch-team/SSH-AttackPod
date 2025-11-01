# Stage 1: Build stage
FROM ubuntu:24.04 AS builder

# Set environment variable for non-interactive installations
ENV DEBIAN_FRONTEND=noninteractive

# Enable 'deb-src' entries and install dependencies
RUN echo "deb-src http://archive.ubuntu.com/ubuntu noble main restricted universe multiverse" >> /etc/apt/sources.list && \
    echo "deb-src http://archive.ubuntu.com/ubuntu noble-updates main restricted universe multiverse" >> /etc/apt/sources.list && \
    echo "deb-src http://archive.ubuntu.com/ubuntu noble-security main restricted universe multiverse" >> /etc/apt/sources.list && \
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
        openssh-server && \
    apt-get clean && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Copy patched sshd binary and configuration from builder stage
COPY --from=builder /src/openssh-*/debian/tmp/usr/sbin/sshd /usr/sbin/sshd

# Create a non-root user
RUN groupadd -r appuser && useradd -r -g appuser -m appuser

# Adjust permissions for SSH and log files
RUN mkdir -p /etc/ssh && chown -R appuser:appuser /etc/ssh && \
    touch /var/log/ssh.log && chown appuser:appuser /var/log/ssh.log

# Set working directory
WORKDIR /home/appuser/code
RUN chown -R appuser:appuser /home/appuser

# Switch to non-root user
USER appuser

# Copy runtime requirements and install them
COPY requirements.txt /home/appuser/code/

# Install python3-venv (required for creating venv)
USER root
RUN apt-get update && apt-get install -y python3-venv && rm -rf /var/lib/apt/lists/*

# Back to appuser for security
USER appuser

# Create virtual environment and install dependencies
RUN python3 -m venv /home/appuser/venv && \
    /home/appuser/venv/bin/pip install --no-cache-dir -r requirements.txt

# Use venv Python and pip as default
ENV PATH="/home/appuser/venv/bin:$PATH"

# Copy application code
COPY monitor.py /home/appuser/code/

# Move sshd to Port 2222
# change /etc/ssh/sshd_config by uncommenting Port 22 and changing it to Port 2222
RUN sed -i.orig -e 's/^#\(Port 22\)/\122/' \
    -e 's/^#\(AddressFamily\).*$/\1 any/' /etc/ssh/sshd_config

# Expose SSH port
# Changed from 22 to 2222
EXPOSE 2222

# Report the version of the openSSH server
RUN sshd -V

# Command to run your application
CMD ["python3", "monitor.py"]
