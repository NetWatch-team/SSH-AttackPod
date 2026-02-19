# NetWatch SSH-AttackPod 

The NetWatch SSH-AttackPod is a modified OpenSSH server that records any attempted username/password combinations along with the source IP. This data is sent to the central NetWatch collector, which processes it and sends out abuse notifications as necessary.

#### Prerequisites
To be able to run a SSH-AttackPod you need: 

 - to have [Docker installed](#1-installation-of-docker)
 - [obtain an API-key](#1-obtain-an-api-key-from-netwatch)
 - public IP address: If the system you are running SSH-AttackPod on is not reachable over the internet you have to configure port forwarding on your firewall


 #### 1. Obtain an API-key from [Netwatch](https://community.netwatch.team/)

To run a SSH-AttackPod you need an API-key to be able to submit your results. To request an API-key:

 - Go to [NetWatch community](https://community.netwatch.team/)
 - Click: **Join the community**. 
 - Enter your *email address* and you will receive your API-key

#### 2. Download the SSH-AttackPod

To download the SSH-AttackPod and all necessary files clone the repository from Github.

```bash
git clone https://github.com/NetWatch-team/SSH-AttackPod.git
```

#### 3. Configure the SSH-AttackPod

In the cloned repository copy the file `template.env` to `.env` and populated with the API-key your received from the Team.

 1. Change the directory:

    ```bash
    cd ~/SSH-AttackPod
    ```
 2. Copy the file:

    ```bash
    cp template.env .env
    ```
 3. Edit the `.env` file and add your API-key:

    ```bash
    NETWATCH_COLLECTOR_AUTHORIZATION=<API_KEY_FROM_NETWATCH_TEAM>
    ```

#### 4. Start the SSH-AttackPod in test-mode
To start the container, run the following commands *in the directory where the repository resides with the file:* `docker-compose.yml` *\[. e.g.:* `~/SSH-AttackPod`*\]*.

This command will start the docker container attached to your shell and enables you to view the logs. 

```bash
docker compose up --force-recreate
```
When you're finished reviewing, you can stop the container with `[Ctrl-C]`.

#### 5. Switch SSH-AttackPod to production mode (non test-mode)

 1. Edit the `.env` file and change NETWATCH_TEST_MODE to false:

    ```bash
    NETWATCH_TEST_MODE=false
    ```
 2. Start SSH-AttackPod in background (detached)

```bash
docker compose up --force-recreate -d && docker compose logs -tf
```
When you're finished reviewing, you can stop the log output with `[Ctrl-C]`.

## Testing the SSH-AttackPod

When your SSH-AttackPod is running, all login attempts are being send to the Netwatch project. **This may include any attempt of you to test the system or when you try to login with your normal username and password for your system!**

If you want to test whether the AttackPod is working as expected, you can enable *TEST_MODE* by adding NETWATCH_TEST_MODE=true to your `.env` file. This will configure the AttackPod to register and submit the attacks, but the backend will discard them and not take further action.

*Please remember to revert this change once you have completed your testing!*


## Data Access

The attacks that your sensor collects are used to create blocklists and to report abusive IPs to the relevant parties to get them taken down. If you would like to use the data for your own purposes, you have multiple ways to access it:

### Block Lists

The NetWatch backend frequently updates lists of IP addresses that have been identified as malicious. These lists are available at: https://api.netwatch.team/blocklist/24h, https://api.netwatch.team/blocklist/48h, https://api.netwatch.team/blocklist/96h and contain all abusive IPs detected in the last 24, 48, and 96 hours respectively. The lists are designed to be integrated with common firewalls, allowing the proactive blocking of abusive IPs.

### Community API

To get direct access to the data that your sensor submitted to the NetWatch backend, you can use the Community API. You can find the API documentation at: https://community-api.netwatch.team. Currently, the API allows you to retrieve the raw data that your sensor submitted to the NetWatch backend, as well as correlated data from other sensors and customized block lists for your environment. (Please be aware that there is a fair use policy in place for the Community API.)

### Daily Attack Summary

On the Daily Attack Summary GitHub repository, you can find a daily export of all abusive IPs and unique credentials seen by all sensors. You can find the repository at: https://github.com/NetWatch-team/Daily-Attack-Summary

### Research & Collaboration

If you are a security researcher or a university student looking for large-scale attack datasets to use within your thesis or other research projects, we support the academic community by providing access to the raw data for non-commercial research purposes. Please reach out to us with a brief description of your project at [contact@netwatch.team](mailto:contact@netwatch.team)



## Additional information

#### Installation of Docker

NetWatch SSH-AttackPod depends on Docker and Docker Compose to be installed. 

To install Docker, follow the [Docker Installation](https://docs.docker.com/engine/install/) instructions. For Ubuntu-based systems, the steps are as follows:

 1. Add Docker's official GPG key and execute the following commands:
 
    ```bash
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
 2. Verify that Docker and Docker Compose are running by using the following commands:

    ```bash
    docker version
    docker compose version
    ```

#### Run SSH-AttackPod on default ssh port 22

If you want to run SSH-AttackPod on ssh's default port 22 you can do by changing the NETWATCH_PORT in the `.env` file

 1. Edit the `.env` file and change NETWATCH_PORT:

    ```bash
    NETWATCH_PORT=22
    ```

If you have already an sshd running it's default port is 22 so you **must** change the port of your sshd to another port. In these instructions we move it to port 2222. You need root privileges to do this. 

**Beware!** If your system is not reachable directly (e.g. it's behind a firewall) and you have a port forwarding to the system ensure that when changing sshd's port that the port forwarding rule in your firewall is changed to the new port! Otherwise you will lose access! 

Depending on Linux distribution you use you may need to reconfigure `/etc/ssh/sshd_config` or `ssh.socket`. 

 + Reconfigure the sshd_config file:
   - Open `sshd_config` with your favourite editor (here it is vim): 
     ```bash
     sudo vim /etc/ssh/sshd_config
     ```
   - Find the line `#Port 22`, remove the `#`, and change the port number to one of your choice *(2222 for example)*. 
   - Restart sshd or reboot your system: 
     ```bash
     sudo systemctl restart sshd
     ```
 + Change port in *ssh.socket*:
   - Edit *ssh.socket*:
     ```
     sudo systemctl edit ssh.socket
     ```
   - Add this text before `### Lines below this comment will be discarded`:
     ```
     [Socket]
     ListenStream=2222
     ```
   - Restart *ssh.socket*:
     ```
     sudo systemctl restart ssh.socket
     ```
   - Verify if *ssh.socket* is running:
     ```
     systemctl status ssh.socket
     ```

#### (Re-)Build SSH-AttackPod from source

If you want to build SSH-AttackPod from source you can do by: 

```bash
docker compose build --no-cache
```

#### RFC 1918 Private IP Filtering

The SSH-AttackPod automatically filters out attacks involving private/local IP addresses to prevent false positives and reduce backend processing load. Attacks are **not reported** to the NetWatch collector if either the source IP or destination IP is a private/non-routable address.

##### Filtered IP Ranges

The following IP ranges are considered private and will cause attacks to be filtered:

- **RFC 1918 Private Networks:**
  - `10.0.0.0/8` (10.0.0.0 - 10.255.255.255)
  - `172.16.0.0/12` (172.16.0.0 - 172.31.255.255)
  - `192.168.0.0/16` (192.168.0.0 - 192.168.255.255)

- **Loopback Addresses:**
  - `127.0.0.0/8` (127.0.0.0 - 127.255.255.255)

- **Link-Local Addresses:**
  - `169.254.0.0/16` (169.254.0.0 - 169.254.255.255)

##### Behavior

When an SSH login attempt is detected and either the source or destination IP is in one of these ranges, the AttackPod will:
1. Log the filtered attack at INFO level: `"Skipping attack from/to private IP - Source: X.X.X.X, Destination: Y.Y.Y.Y, User: username"`
2. **Not** submit the attack to the NetWatch collector

This filtering happens automatically and requires no configuration.