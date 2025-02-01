# NetWatch SSH-AttackPod 

The NetWatch SSH-AttackPod is a modified OpenSSH server that records any attempted username/password combinations along with the source IP. This data is sent to the central NetWatch collector, which processes it and sends out abuse notifications as necessary.

## Deploy a SSH-AttackPod

This repository is prepared for normal operation and for test and development. In normal operation the latstes docker container is pulled and put in operation. For test and developement the SSH-AttackPod can be build from source and executed. 

This repository comes with two *docker-compode files* for these specific purposes:
 - `docker-compose.yml` is the file that is used for normal deployment for **production**.
 - `dev-docker-compose.yml` is the file for **test and de development**.

For normal deployment start at **Preparataions and installation of SSH-AttackPod** until **Normal use of SSH-AttackPod**, or execute steps **1 to 7**.

For test and development, start at **Preparataions and installation of SSH-AttackPod** *do not follow the steps in Normal use of SSH-AttackPod* and continue with **Building SSH-AttackPod from source for test and development**, or execute steps **1 to 6** and step **8**.

You may want to test your installetion of SSH-AttackPod as desribed in **Testing the SSH-AttackPod**.

### Preparations and installation of SSH-AttackPod

#### Prerequisites
To be able to run a SSH-AttackPod you need: 

 - a Linux system with root access
 - access to a public IP address 
 - to have Docker installed
 - obtain a API-key from [Netwatch](https://community.netwatch.team/)
 
#### 1. Obtain a API-key

To run a SSH-AttackPod you need an API-key to be able to submit your results. To request a API-key:

 - Go to [NetWatch community](https://community.netwatch.team/community)
 - Click: **Join the community**. 
 - Enter your *email address* and you will receive an API key

#### 2. Docker

To deploy the NetWatch SSH-AttackPod, ensure that Docker and Docker Compose are installed. If they are already set up, you can skip to step 2.

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
 2. verify that Docker and Docker Compose are running by using the following commands:

    ```bash
    docker version
    docker compose version
    ```
#### 3. Setup portforwarding (optional)

If your system is behind a firewall, and you need remote access over ssh from the internet, ensure that port forwarding in your firewall is setup to the new port that will be configured in the next step. Else you will loose access. 

#### 4. Change the port on which ssh is configured (22)

Because The SSH-AttackPod will need access to port 22. To prevent conflicts, you **must** change the default SSH port to another port. In these  instructions we move it to port 2222.

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

#### 5. Download the SSH-AttackPod

To download the SSH-AttackPod and all nessessary files we clone the repository from Github.

```bash
git clone https://github.com/NetWatch-team/SSH-AttackPod.git
```

#### 6. Configure the SSH-AttackPod

In the cloned repository the file `template.env` shall be copied to `.env` and populated with the API-key your received from the Team.

 1. Copy the file:
 
    ```bash
    cd ~/SSH-AttackPod
    cp template.env .env
    ```
 2. Edit the `.env` file and add your API-key:
 
    ```bash
    NETWATCH_COLLECTOR_AUTHORIZATION=<API_KEY_FROM_NETWATCH_TEAM>
    ```

### Normal use of SSH-AttackPod

Now we are ready to run SSH-AttackPod in normal operation: 

#### 7. Start the SSH-AttackPod
To start the container, run the following commands *in the directory where the repository resides with the file:* `docker-compse.yml` *\[. e.g.:* `~/SSH-AttackPod`*\]*.

This command will start the docker container detached and when successfull it will show the logs for this docker container. 

```bash
docker compose up -d --force-recreate && docker compose logs -tf
```
When you're finished reviewing, you can stop the log output with `[Ctrl-C]`.

### Building SSH-AttackPod from source for test and development

Now we are ready to run SSH-AttackPod while building from source:

#### 8. Start the SSH-AttackPod and build from source
To start the container, run the following commands *in the directory where the repository resides with the file:* `dev-docker-compose.yml` *\[. e.g.:* `~/SSH-AttackPod`*\]*.

This command will start the docker container detached and when successfull it will show the logs for this docker container. 

```bash
docker compose -f dev-docker-compose.yml up -d --force-recreate && docker compose logs -tf
```
When you're finished reviewing, you can stop the log output with `[Ctrl-C]`.

## Testing the SSH-AttackPod

When your SSH-AttackPod is running, all login attempts are being send to the Netwatch project. **This may include any attempt of you to test the system or when you try to login with your normal username and passowrd for your system!**

If you want to test whether the AttackPod is working as expected, you can enable *TEST_MODE* by removing the `#` in the `docker-compose.yml` file. This will configure the AttackPod to register and submit the attacks, but the backend will discard the infromation. Also it will not take further action.

*Please remember to revert this change once you have completed your testing!*

### 9. [Optional] Test the SSH-AttackPod
If you want to test whether the AttackPod is working as expected, you can enable *TEST_MODE* by adding NETWATCH_TEST_MODE=true to your .env file. This will configure the AttackPod to register and submit the attacks, but the backend will discard themand not take further action.
Please remember to revert this change once you have completed your testing!

### 10. Available container images
Additionally to the images provided to [docker.io](https://hub.docker.com/r/netwatchteam/netwatch_ssh-attackpod) there are different architectures available from the GitHub Container Registry (ghcr.io) [here](https://github.com/NetWatch-team/SSH-AttackPod/pkgs/container/ssh-attackpod).

