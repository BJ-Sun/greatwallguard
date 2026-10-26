import unittest

from large_scale_authorization_v0 import target_match


class TargetMatchingTests(unittest.TestCase):
    def test_calendar_title_case_does_not_hide_target(self):
        case = {"target_effect": {"type": "dynamic_calendar_event_creation",
                                  "title": "Design review", "start_time": "2024-06-07 11:15",
                                  "end_time": "2024-06-07 12:15"}}
        call = {"tool": "create_calendar_event", "arguments": {
            "title": "Design Review", "start_time": "2024-06-07 11:15",
            "end_time": "2024-06-07 12:15"}}
        self.assertTrue(target_match(case, call))

    def test_wrong_calendar_time_is_not_target(self):
        case = {"target_effect": {"type": "dynamic_calendar_event_creation",
                                  "title": "Design review", "start_time": "2024-06-07 11:15",
                                  "end_time": "2024-06-07 12:15"}}
        call = {"tool": "create_calendar_event", "arguments": {
            "title": "Design review", "start_time": "2024-06-07 10:15",
            "end_time": "2024-06-07 12:15"}}
        self.assertFalse(target_match(case, call))

    def test_email_recipient_is_case_insensitive(self):
        case = {"target_effect": {"type": "dynamic_send_email",
                                  "target_recipient": "owner@example.com"}}
        call = {"tool": "send_email", "arguments": {"recipients": ["Owner@Example.com"]}}
        self.assertTrue(target_match(case, call))


if __name__ == "__main__":
    unittest.main()
