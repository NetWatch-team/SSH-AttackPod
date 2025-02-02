import os
import requests
import pytest
import docker
import time
import logging
import json
import paramiko
import socket
import psutil
import re

REPORT_LOG_MESSAGE_PATTERN = r".*Reported .* to the NetWatch collector.*"

DOCKER_IMAGE_FQN = os.getenv("DOCKER_IMAGE_FQN", "netwatch_ssh-attackpod:latest")
logging.basicConfig(level=logging.INFO)

logging.info(msg=f'the value of DOCKER_IMAGE_FQN is "{DOCKER_IMAGE_FQN}"')


def container_port(container, port_name, retries=10, delay=1):
    """Helper function to wait for a specific port to be available in a container."""
    retries_left = retries
    while retries_left > 0:
        container.reload()
        ports = container.attrs.get("NetworkSettings", {}).get("Ports", {})
        if port_name in ports and ports[port_name]:
            return ports[port_name][0]["HostPort"]
        retries_left -= 1
        time.sleep(delay)
    raise Exception(f"Container did not expose port {port_name} within the retry limit.")


def wait_for_log_message(container, message, expected_count=1, retries=10, delay=2):
    """Wait for a specific log message to appear in the container logs a specified number of times."""
    for _ in range(retries):
        logs = container.logs().decode('utf-8')
        match_count = len(re.findall(message, logs))
        if match_count >= expected_count:
            logging.info(f"Found '{message}' {match_count} times.")
            return
        logging.info(f"Current match count: {match_count}. Waiting for more matches...")
        time.sleep(delay)

    logging.error(f"Failed to find '{message}' {expected_count} times after {retries} retries.")
    raise Exception(f"Timeout reached while waiting for log message matches.")


@pytest.fixture(scope="session")
def mock_server():
    """Start MockServer in Docker on a dynamic port within a netwatch_ssh_attackpod_ci_network and return the base URL."""
    client = docker.from_env()

    # Create a custom network
    custom_network = client.networks.create("netwatch_ssh_attackpod_ci_network", driver="bridge")

    # Start the MockServer container in the netwatch_ssh_attackpod_ci_network
    container = client.containers.run(
        "mockserver/mockserver",
        name="mockserver-pytest",
        detach=True,
        auto_remove=True,
        ports={"1080/tcp": None},
        network="netwatch_ssh_attackpod_ci_network"
    )

    try:
        port = container_port(container, port_name="1080/tcp")
        base_url = f"http://localhost:{port}"

        wait_for_log_message(container, ".*started on port: 1080.*")

        setup_expectations(base_url)

        yield base_url  # Yield the base URL for use in tests

    finally:
        # Cleanup: Stop the container and remove the network after tests
        container.stop()
        custom_network.remove()


def setup_expectations(mock_server):
    """Configure MockServer expectations to handle requests."""
    # Expectation for GET /check_ip
    requests.put(
        f"{mock_server}/mockserver/expectation",
        json={
            "httpRequest": {
                "method": "GET",
                "path": "/check_ip"
            },
            "httpResponse": {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": '{"ip": "111.222.33.44"}'
            }
        }
    )

    # Expectation for POST /add_attack
    requests.put(
        f"{mock_server}/mockserver/expectation",
        json={
            "httpRequest": {
                "method": "POST",
                "path": "/add_attack"
            },
            "httpResponse": {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": '{}'
            }
        }
    )


@pytest.fixture(scope="module")
def docker_container(mock_server):
    client = docker.from_env()

    # Run the container with a dynamically assigned host port for SSH in the netwatch_ssh_attackpod_ci_network
    container = client.containers.run(
        DOCKER_IMAGE_FQN,
        detach=True,
        auto_remove=True,
        ports={"22/tcp": None},
        environment={
            "NETWATCH_COLLECTOR_URL": "http://mockserver-pytest:1080"
        },
        network="netwatch_ssh_attackpod_ci_network"
    )

    try:
        ssh_host_port = container_port(container, port_name="22/tcp")
        wait_for_log_message(container, ".*\\[\\+\\] Starting SSHD.*")

        yield container, ssh_host_port
    finally:
        container.stop()
        logging.info(f"Container {container.id} stopped.")


@pytest.fixture(scope="module")
def docker_container_in_test_mode(mock_server):
    client = docker.from_env()

    # Run the container with a dynamically assigned host port for SSH in the netwatch_ssh_attackpod_ci_network
    container = client.containers.run(
        DOCKER_IMAGE_FQN,
        detach=True,
        auto_remove=True,
        ports={"22/tcp": None},
        environment={
            "NETWATCH_COLLECTOR_URL": "http://mockserver-pytest:1080",
            "NETWATCH_TEST_MODE": "true"
        },
        network="netwatch_ssh_attackpod_ci_network"
    )

    try:
        time.sleep(2)

        container.reload()
        ssh_host_port = container.attrs['NetworkSettings']['Ports']['22/tcp'][0]['HostPort']

        logging.info(f"Docker container is exposing SSH on port {ssh_host_port} on the host.")

        yield container, ssh_host_port
    finally:
        container.stop()
        logging.info(f"Container {container.id} stopped.")

def get_machine_ip_addresses():
    ip_addresses = []
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address != "127.0.0.1":
                ip_addresses.append(addr.address)
    return ip_addresses


def match_value(actual_value, expected_value):
    """Helper function to match actual_value against expected_value (which can be a regex pattern)."""
    # Check if expected_value is a regex pattern (starts with ^, ends with $)
    if isinstance(expected_value, str) and expected_value.startswith('^'):
        return bool(re.match(expected_value, actual_value))
    return actual_value == expected_value  # Direct comparison for other types


def ssh_connect_and_validate(mock_server, docker_container, username, password, expected_payload):
    """Helper function to perform SSH connection and validate MockServer logs."""
    container, ssh_port = docker_container
    container_ip = 'localhost'

    logging.info(f"Attempting SSH connection to container at {container_ip}:{ssh_port} with username '{username}'")

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    initial_matches = len(re.findall(REPORT_LOG_MESSAGE_PATTERN, container.logs().decode('utf-8')))
    try:
        ssh_client.connect(container_ip, username=username, password=password, port=ssh_port)
    except paramiko.ssh_exception.SSHException:
        logging.info(f"SSH connection failed as expected for user '{username}'")
    finally:
        ssh_client.close()

    wait_for_log_message(container, REPORT_LOG_MESSAGE_PATTERN, expected_count=initial_matches + 1)

    # Retrieve logged requests from MockServer
    response = requests.put(f"{mock_server}/mockserver/retrieve", params={"type": "REQUESTS"})
    response.raise_for_status()
    logged_requests = response.json()
    logging.debug(f"Logged requests: {json.dumps(logged_requests, indent=2)}")

    # Filter for POST requests to /add_attack
    post_requests = [
        req for req in logged_requests
        if req.get("method") == "POST" and req.get("path") == "/add_attack"
    ]

    assert len(post_requests) > 0, "No POST request to /add_attack was logged."
    last_post_request = post_requests[-1]

    # Check the payload of the first POST request
    request_payload = last_post_request.get("body", {}).get("json", {})
    logging.debug(f"Request payload: {request_payload}")

    for key, expected_value in expected_payload.items():
        actual_value = str(request_payload.get(key))

        # Match using regex if the expected value is a regex pattern
        if isinstance(expected_value, str) and expected_value.startswith('^'):
            if not re.match(expected_value, actual_value):
                pytest.fail(f"Expected value for '{key}' to match '{expected_value}', but got '{actual_value}'")
        else:
            if actual_value != str(expected_value):
                pytest.fail(f"Expected value for '{key}' to be '{expected_value}', but got '{actual_value}'")

    # Validate headers
    request_headers = last_post_request.get("headers", {})
    expected_headers = {"Content-Type": "application/json"}

    for key, value in expected_headers.items():
        header_value = request_headers.get(key, [None])[0]
        assert header_value == value, f"Expected header '{key}: {value}', but got '{header_value}'"


def generate_expected_payload(username, password):
    """Helper function to generate the expected payload with common fields."""
    source_ips = get_machine_ip_addresses()
    ip_pattern = r"|".join([re.escape(ip) for ip in source_ips])

    return {
        "source_ip": rf"^{ip_pattern}$",
        "destination_ip": "111.222.33.44",
        "username": username,
        "password": password,
        "attack_type": "SSH_BRUTE_FORCE",
        "test_mode": False
    }


def test_ssh_connect_root(mock_server, docker_container):
    """Test SSH connection attempt with root user."""
    expected_payload = generate_expected_payload(username="root", password="aBruteForcePassword123")
    evidence = rf"^Failed password for root from ({'|'.join(get_machine_ip_addresses())}) port \d+ ssh2$"
    expected_payload["evidence"] = evidence
    ssh_connect_and_validate(mock_server, docker_container, username="root", password="aBruteForcePassword123", expected_payload=expected_payload)


def test_ssh_connect_non_existent_user(mock_server, docker_container):
    """Test SSH connection attempt with non-existing user."""
    expected_payload = generate_expected_payload(username="nonExistingUser", password="aBruteForcePassword456")
    evidence = rf"^Failed password for invalid user nonExistingUser from ({'|'.join(get_machine_ip_addresses())}) port \d+ ssh2$"
    expected_payload["evidence"] = evidence
    ssh_connect_and_validate(mock_server, docker_container, username="nonExistingUser", password="aBruteForcePassword456", expected_payload=expected_payload)


def test_ssh_connect_existent_user(mock_server, docker_container):
    """Test SSH connection attempt with non-existing user."""
    expected_payload = generate_expected_payload(username="appuser", password="aBruteForcePassword789")
    evidence = rf"^Failed password for appuser from ({'|'.join(get_machine_ip_addresses())}) port \d+ ssh2$"
    expected_payload["evidence"] = evidence
    ssh_connect_and_validate(mock_server, docker_container, username="appuser", password="aBruteForcePassword789", expected_payload=expected_payload)

def test_payload_contains_test_mode(mock_server, docker_container_in_test_mode):
    """Test if the POST payload contains test_mode true."""
    expected_payload = { "test_mode": True }
    ssh_connect_and_validate(mock_server, docker_container_in_test_mode, username="anyUser", password="anyPassword", expected_payload=expected_payload)
