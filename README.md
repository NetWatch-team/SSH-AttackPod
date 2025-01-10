# NetWatch SSH-AttackPod 

The NetWatch SSH-AttackPod is a modified OpenSSH server that records any attempted username/password combinations along with the source IP. This data is sent to the central NetWatch collector, which processes it and sends out abuse notifications as necessary.

## Deployment

### 1. Prerequisites
To deploy the NetWatch SSH-AttackPod, ensure that Docker and Docker Compose are installed. If they are already set up, you can skip to step 2.

To install Docker, follow the instructions here: [Docker Installation](https://docs.docker.com/engine/install/). For Ubuntu-based systems, the steps are as follows:

```bash
# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```
Once installed, verify that Docker and Docker Compose are running by using the following commands:

```bash
docker version
docker compose version
```
### 2. Move SSH Port Away from 22
The SSH-AttackPod will need access to port 22. To prevent conflicts, you must change the default SSH port. Edit the sshd_config file:

```bash
sudo vim /etc/ssh/sshd_config
```
Find the line #Port 22, remove the #, and change the port number to one of your choice. Ensure your firewall allows access to this new port. Afterward, restart the SSH service:

```bash
sudo systemctl restart sshd
```
Alternatively, you can reboot your system.

### 4. Configure the SSH-AttackPod
Create a folder for the SSH-AttackPod at your preferred location. For this example, we’ll use /opt/:

```bash
mkdir -p /opt/NetWatch/AttackPods/SSH/
cd /opt/NetWatch/AttackPods/SSH/
```
Next, create the docker-compose.yml file to store the configuration and facilitate container management:

```bash
echo 'version: "3"

services:
  NetWatchSSHAttackPod:
    image: netwatchteam/netwatch_ssh-attackpod:latest
    container_name: netwatch_ssh-attackpod 
    environment:
      NETWATCH_COLLECTOR_AUTHORIZATION: ${NETWATCH_COLLECTOR_AUTHORIZATION}
      NETWATCH_COLLECTOR_URL: "https://api.netwatch.team"
      NETWATCH_TEST_MODE: ${NETWATCH_TEST_MODE:-false}
    restart: unless-stopped
    ports:
      - "22:22"
    deploy:
      resources:
        limits:
          cpus: "0.75"
          memory: 750M
        reservations:
          cpus: "0.25"
          memory: 200M
    logging:
      driver: "json-file"
      options:
        max-size: "10M"
        max-file: "2"' > ./docker-compose.yml
```
Next, create a .env file to store the API key you received from the NetWatch team. Use your preferred text editor to create the file and add the following content:

```bash
NETWATCH_COLLECTOR_AUTHORIZATION=<API_KEY_FROM_NETWATCH_TEAM>
```

### 5. Start the SSH-AttackPod
To start the container, run the following commands:

```bash
docker compose up -d --force-recreate && docker compose logs -tf
```

This will start the container in detached mode and display the logs. To check if everything is working as expected, you can monitor the logs. When you're finished reviewing, you can stop the log output with Ctrl + C.


### 6. [Optional] Test the SSH-AttackPod
If you want to test whether the AttackPod is working as expected, you can enable *TEST_MODE* by adding NETWATCH_TEST_MODE=true to your .env file. This will configure the AttackPod to register and submit the attacks, but the backend will discard themand not take further action.
Please remember to revert this change once you have completed your testing!
