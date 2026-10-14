import unittest
from unittest.mock import Mock, patch

from tests.splunk.test_upgrade import retry_kv_initialization


class UpgradeReadinessTests(unittest.TestCase):
    @patch("tests.splunk.test_upgrade.time.sleep")
    def test_initializing_kv_store_can_become_ready(self, sleep):
        request = Mock(
            side_effect=[(503, b"KV Store is initializing"), (201, b"created")]
        )
        self.assertEqual(retry_kv_initialization(request), (201, b"created"))
        self.assertEqual(request.call_count, 2)
        sleep.assert_called_once_with(2)

    def test_permission_errors_and_other_failures_are_not_retried(self):
        for response in [(403, b"denied"), (503, b"other failure")]:
            with self.subTest(response=response):
                request = Mock(return_value=response)
                self.assertEqual(retry_kv_initialization(request), response)
                request.assert_called_once_with()

    def test_readiness_has_a_deadline(self):
        response = (503, b"KV Store is initializing")
        request = Mock(return_value=response)
        self.assertEqual(retry_kv_initialization(request, timeout=0), response)
        request.assert_called_once_with()
