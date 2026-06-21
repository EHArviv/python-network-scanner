import unittest
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.network_scanner import parse_ports
from src.network_scanner import validate_port
from src.network_scanner import get_service_hint
from src.network_scanner import calculate_port_severity
from src.network_scanner import get_port_recommendation


class TestNetworkScannerLogic(unittest.TestCase):
    def test_parse_single_ports(self):
        ports = parse_ports("22,80,443")
        self.assertEqual(ports, [22, 80, 443])

    def test_parse_port_range(self):
        ports = parse_ports("20-22")
        self.assertEqual(ports, [20, 21, 22])

    def test_validate_port(self):
        self.assertTrue(validate_port(443))
        self.assertFalse(validate_port(0))
        self.assertFalse(validate_port(70000))

    def test_service_hint(self):
        self.assertEqual(get_service_hint(22), "SSH")
        self.assertEqual(get_service_hint(443), "HTTPS")
        self.assertEqual(get_service_hint(65000), "unknown")

    def test_high_risk_open_port(self):
        severity = calculate_port_severity(3389, "open")
        self.assertEqual(severity, "High")

    def test_medium_risk_open_port(self):
        severity = calculate_port_severity(22, "open")
        self.assertEqual(severity, "Medium")

    def test_closed_port_info(self):
        severity = calculate_port_severity(3389, "closed_or_filtered")
        self.assertEqual(severity, "Info")

    def test_recommendation_for_closed_port(self):
        recommendation = get_port_recommendation(22, "closed_or_filtered")
        self.assertIn("No action required", recommendation)


if __name__ == "__main__":
    unittest.main()
