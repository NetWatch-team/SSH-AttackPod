import unittest
import sys
import os

# Add the src directory to the path so we can import monitor
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from monitor import is_private_ip


class TestRFC1918Filtering(unittest.TestCase):
    """Test RFC 1918 private IP address detection"""

    def test_rfc1918_10_network(self):
        """Test 10.0.0.0/8 network"""
        self.assertTrue(is_private_ip("10.0.0.1"))
        self.assertTrue(is_private_ip("10.255.255.255"))
        self.assertTrue(is_private_ip("10.123.45.67"))

    def test_rfc1918_172_network(self):
        """Test 172.16.0.0/12 network"""
        self.assertTrue(is_private_ip("172.16.0.1"))
        self.assertTrue(is_private_ip("172.31.255.255"))
        self.assertTrue(is_private_ip("172.20.10.5"))
        # These are NOT in the RFC 1918 range
        self.assertFalse(is_private_ip("172.15.255.255"))
        self.assertFalse(is_private_ip("172.32.0.1"))

    def test_rfc1918_192_network(self):
        """Test 192.168.0.0/16 network"""
        self.assertTrue(is_private_ip("192.168.0.1"))
        self.assertTrue(is_private_ip("192.168.255.255"))
        self.assertTrue(is_private_ip("192.168.1.100"))

    def test_loopback_addresses(self):
        """Test 127.0.0.0/8 loopback network"""
        self.assertTrue(is_private_ip("127.0.0.1"))
        self.assertTrue(is_private_ip("127.255.255.255"))
        self.assertTrue(is_private_ip("127.0.0.2"))

    def test_link_local_addresses(self):
        """Test 169.254.0.0/16 link-local network"""
        self.assertTrue(is_private_ip("169.254.0.1"))
        self.assertTrue(is_private_ip("169.254.255.255"))
        self.assertTrue(is_private_ip("169.254.123.45"))

    def test_public_ip_addresses(self):
        """Test that public IPs are correctly identified as non-private"""
        self.assertFalse(is_private_ip("8.8.8.8"))  # Google DNS
        self.assertFalse(is_private_ip("1.1.1.1"))  # Cloudflare DNS
        self.assertFalse(is_private_ip("151.101.1.140"))  # Fastly
        self.assertFalse(is_private_ip("93.184.216.34"))  # Example.com
        self.assertFalse(is_private_ip("111.222.33.44"))  # Generic public IP

    def test_invalid_ip_addresses(self):
        """Test that invalid IPs return False (fail-safe)"""
        self.assertFalse(is_private_ip("not.an.ip.address"))
        self.assertFalse(is_private_ip("999.999.999.999"))
        self.assertFalse(is_private_ip(""))
        self.assertFalse(is_private_ip("192.168"))
        self.assertFalse(is_private_ip("invalid"))


if __name__ == '__main__':
    unittest.main()
