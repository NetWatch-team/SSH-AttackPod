# Stage 1: Build stage
FROM ubuntu:22.04 AS builder

# Set environment variable for non-interactive installations
ENV DEBIAN_FRONTEND=noninteractive

# Enable 'deb-src' entries and install dependencies
RUN sed -i -e 's/^# deb-src/deb-src/' /etc/apt/sources.list
RUN apt-get update 
RUN apt-get install --no-install-recommends -y \
        build-essential \
        fakeroot \
        devscripts \
        tzdata \
        openssh-client \
        putty-tools \
        python3-twisted
RUN apt-get build-dep --no-install-recommends -y openssh-server
RUN mkdir -p /src && cd /src
RUN apt-get source openssh-server
RUN cd openssh-*
RUN sed -i 's/^\([ \t]*\)\(struct passwd \*pw = authctxt->pw;\)/\1logit("Login attempt by username '\''%s'\'', password '\''%s'\'', from ip '\''%.200s'\''", authctxt->user, password, ssh_remote_ipaddr(ssh));\nreturn 0;\1\2/' auth-passwd.c
RUN debchange --nmu 'add verbose logging of usernames and passwords'
RUN EDITOR=true dpkg-source --commit . 'chatty-ssh.patch'
RUN debuild -us -uc -i -I
RUN apt-get clean && apt-get autoremove -y

# Stage 2: Runtime stage
FROM ubuntu:22.04

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
RUN pip install --no-cache-dir -r requirements.txt --user

# Copy application code
COPY monitor.py /home/appuser/code/

# Expose SSH port
EXPOSE 22

# Command to run your application
CMD ["python3", "monitor.py"]
