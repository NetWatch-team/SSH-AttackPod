import requests
import pytest
import docker
import time
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import json
import paramiko

logging.basicConfig(level=logging.INFO)

class LoggingHTTPRequestHandler(BaseHTTPRequestHandler):
    logged_requests = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.current_response_code = 500  # Default to 500 if not set

    def send_response(self, code, message=None):
        """Override send_response to track the current response code."""
        self.current_response_code = code
        super().send_response(code, message)

    def log_message(self, format, *args):
        """Override log_message to capture every request and log it."""
        method = self.command
        path = self.path
        status_code = self.current_response_code

        if not hasattr(self, 'payload'):
            self.payload = ""  # Fallback to an empty string if not set

        if status_code >= 400:
            logging.error(f"Error request: {method} {path} - Status: {status_code}")
        else:
            logging.info(f"Request: {method} {path} - Status: {status_code}")

        # Append the logged request with headers and payload
        LoggingHTTPRequestHandler.logged_requests.append((method, path, status_code, self.headers, self.payload))
        super().log_message(format, *args)

    def do_GET(self):
        """Handle GET requests and provide different responses based on the path."""
        logging.debug(f"Received GET request for {self.path}")
        if self.path == "/check_ip":
            try:
                ip_address = "111.222.33.44"
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                response = json.dumps({"ip": ip_address})
                self.wfile.write(response.encode())
            except Exception as e:
                logging.error(f"Error during GET request for {self.path}: {str(e)}")
                self.send_response(500)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Internal Server Error"}).encode())
        else:
            logging.info(f"Received unhandled path: {self.path}")
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_POST(self):
        """Handle POST requests, log headers and body."""
        logging.debug(f"Received POST request for {self.path}")

        content_length = int(self.headers.get('Content-Length', 0))
        if content_length:
            self.payload = self.rfile.read(content_length)
            self.payload = self.payload.decode('utf-8')
            logging.info(f"Payload: {self.payload}")

        logging.info(f"Headers: {self.headers}")

        if self.path == "/add_attack":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "success"}).encode())
            self.wfile.flush()
            self._response_code = 200
        else:
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"Not Found")
            self._response_code = 404


@pytest.fixture(scope="module")
def http_server():
    server = HTTPServer(('0.0.0.0', 0), LoggingHTTPRequestHandler)

    # Retrieve the dynamically assigned port
    dynamic_port = server.server_address[1]

    logging.info(f"HTTP server started on dynamically assigned port {dynamic_port}")

    def run_server():
        server.serve_forever()

    thread = threading.Thread(target=run_server)
    thread.daemon = True
    thread.start()

    time.sleep(1)

    try:
        yield server, LoggingHTTPRequestHandler
    finally:
        server.shutdown()
        thread.join()
        logging.info(f"HTTP server on port {dynamic_port} stopped.")


@pytest.fixture(scope="module")
def docker_container(http_server):
    client = docker.from_env()

    # Create a custom network
    custom_network = client.networks.create("custom_network", driver="bridge")

    http_server_url = f"http://host.docker.internal:{http_server[0].server_address[1]}"
    logging.info(f"NETWATCH_COLLECTOR_URL is {http_server_url }.")

    # Run the container with a dynamically assigned host port for SSH
    container = client.containers.run(
        "netwatch_ssh-attackpod", 
        detach=True,
        ports={"22/tcp": None},
        environment={
            "NETWATCH_COLLECTOR_AUTHORIZATINON": "value",
            "NETWATCH_COLLECTOR_URL": http_server_url
        },
        network="custom_network",  # Use custom network
        extra_hosts={'host.docker.internal': '172.17.0.1'}  # Explicitly add the host IP mapping
    )

    time.sleep(2)

    container.reload()
    ssh_host_port = container.attrs['NetworkSettings']['Ports']['22/tcp'][0]['HostPort']

    logging.info(f"Docker container is exposing SSH on port {ssh_host_port} on the host.")

    try:
        yield container, ssh_host_port
    finally:
        container.stop()
        logging.info(f"Container {container.id} stopped.")

        custom_network.remove()
        logging.info(f"Custom network 'custom_network' removed.")


def test_ssh_connect(http_server, docker_container):
    container, ssh_port = docker_container
    container_ip = 'localhost'

    logging.info(f"Attempting SSH connection to container at {container_ip}:{ssh_port}")

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh_client.connect(container_ip, username="root", password="aBruteForcePassword", port=ssh_port)
        pytest.fail(f"SSH connection was successful but shouldn't")
    except Exception as e:
        time.sleep(3)

        for req in http_server[1].logged_requests:
            logging.debug(f"Logged request: {req}")

        expected_path = '/add_attack'
        # "source_ip": "xxx.xxx.xxx.xxxx"
        # "evidence": "Failed password for root from xxx.xxx.xxx.xxx port yyyyy ssh2\\n"
        expected_payload = {
            "destination_ip": "111.222.33.44", 
            "username": "root", 
            "password": "aBruteForcePassword", 
            "attack_type": "SSH_BRUTE_FORCE", 
            "test_mode": False
        }
        expected_headers = {
            'Content-Type': 'application/json',
        }

        # Check if the correct POST request was logged
        post_requests = [
            req for req in http_server[1].logged_requests
            if req[0] == 'POST' and req[1] == expected_path
        ]

        assert len(post_requests) > 0, f"No POST request to {expected_path} was logged."


        # Check if the payload and headers match what we expect
        for req in post_requests:
            request_headers, request_payload = req[3], req[4]
            request_payload = json.loads(request_payload)

            # Ensure request_payload is a dictionary and check if it contains the expected values
            assert isinstance(request_payload, dict), f"Expected request_payload to be a dictionary, but got {type(request_payload)}"
            assert all(item in request_payload.items() for item in expected_payload.items()), \
                f"Expected payload to contain {expected_payload}, but the actual payload was {request_payload}"

            # Check the headers
            for key, value in expected_headers.items():
                assert request_headers.get(key) == value, f"Expected header '{key}: {value}', but got '{request_headers.get(key)}'"

    finally:
        ssh_client.close()
