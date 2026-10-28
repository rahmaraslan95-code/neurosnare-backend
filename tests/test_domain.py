import unittest
from app import domain

class DomainTests(unittest.TestCase):
    def test_event_filter_by_severity_and_query(self):
        rows = domain.filtered(domain.EVENTS, query="SSH", severity="critical")
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["kind"], "ssh_bruteforce")
    def test_alert_status_update_and_missing_id(self):
        before = domain.ALERTS[0]["status"]
        updated = domain.update_alert("alt-1", "resolved")
        self.assertEqual(updated["status"], "resolved")
        self.assertIsNone(domain.update_alert("unknown", "open"))
        domain.update_alert("alt-1", before)
    def test_reject_invalid_status(self):
        with self.assertRaises(ValueError):
            domain.update_alert("alt-1", "blocked")
    def test_overview_is_deterministic(self):
        value = domain.overview()
        self.assertEqual(value["total_events"], 12)
        self.assertEqual(value["total_alerts"], 8)
        self.assertEqual(sum(value["severity_counts"].values()), 12)
    def test_search_does_not_mutate_dataset(self):
        rows = domain.filtered(domain.EVENTS, query="lab-sensor")
        rows[0]["summary"] = "changed"
        self.assertNotEqual(domain.EVENTS[0]["summary"], "changed")

if __name__ == "__main__":
    unittest.main()

