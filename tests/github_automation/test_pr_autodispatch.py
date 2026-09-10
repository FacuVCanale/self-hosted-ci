import unittest

from github_automation.pr_autodispatch import (
    Action,
    AutoDispatchError,
    OpenPullRequest,
    plan,
)

HEAD_A = "a" * 40
HEAD_B = "b" * 40
HEAD_C = "c" * 40


def approval(number, head, state):
    return {"pr_number": number, "head_sha": head, "state": state}


class PlanTests(unittest.TestCase):
    def test_a_fresh_open_pull_request_is_approved_once(self):
        actions = plan(
            open_pull_requests=[OpenPullRequest(7, HEAD_A)], approvals=[]
        )
        self.assertEqual(
            actions, (Action("approve", 7, HEAD_A, "new pull request head"),)
        )

    def test_an_already_active_head_is_left_alone(self):
        actions = plan(
            open_pull_requests=[OpenPullRequest(7, HEAD_A)],
            approvals=[approval(7, HEAD_A, "pending")],
        )
        self.assertEqual(actions, ())

    def test_a_new_commit_revokes_the_stale_approval_before_approving(self):
        actions = plan(
            open_pull_requests=[OpenPullRequest(7, HEAD_B)],
            approvals=[approval(7, HEAD_A, "claimed")],
        )
        self.assertEqual(
            actions,
            (
                Action("revoke", 7, HEAD_A, "superseded by a newer commit"),
                Action("approve", 7, HEAD_B, "new pull request head"),
            ),
        )
        self.assertEqual([action.kind for action in actions], ["revoke", "approve"])

    def test_a_settled_head_is_never_re_approved(self):
        for state in ("completed", "failed", "revoked", "expired"):
            with self.subTest(state=state):
                self.assertEqual(
                    plan(
                        open_pull_requests=[OpenPullRequest(7, HEAD_A)],
                        approvals=[approval(7, HEAD_A, state)],
                    ),
                    (),
                )

    def test_a_settled_older_head_does_not_block_the_current_one(self):
        actions = plan(
            open_pull_requests=[OpenPullRequest(7, HEAD_B)],
            approvals=[approval(7, HEAD_A, "completed")],
        )
        self.assertEqual(
            actions, (Action("approve", 7, HEAD_B, "new pull request head"),)
        )

    def test_an_approval_for_a_closed_pull_request_is_revoked(self):
        actions = plan(
            open_pull_requests=[], approvals=[approval(7, HEAD_A, "pending")]
        )
        self.assertEqual(actions, (Action("revoke", 7, HEAD_A, "closed"),))

    def test_work_is_never_cancelled_across_pull_requests(self):
        actions = plan(
            open_pull_requests=[OpenPullRequest(7, HEAD_A), OpenPullRequest(9, HEAD_B)],
            approvals=[approval(7, HEAD_A, "claimed")],
        )
        # PR 9 queues behind the running PR 7 instead of displacing it.
        self.assertEqual(
            actions, (Action("approve", 9, HEAD_B, "new pull request head"),)
        )

    def test_several_fresh_pull_requests_queue_in_number_order(self):
        actions = plan(
            open_pull_requests=[
                OpenPullRequest(9, HEAD_B),
                OpenPullRequest(7, HEAD_A),
                OpenPullRequest(11, HEAD_C),
            ],
            approvals=[],
        )
        self.assertEqual([action.pr_number for action in actions], [7, 9, 11])

    def test_a_head_that_is_not_a_full_sha_is_refused(self):
        for head in ("abc", "A" * 40, "", "g" * 40):
            with self.subTest(head=head), self.assertRaises(AutoDispatchError):
                OpenPullRequest(7, head)

    def test_a_non_positive_pull_request_number_is_refused(self):
        for number in (0, -1, True, "7"):
            with self.subTest(number=number), self.assertRaises(AutoDispatchError):
                OpenPullRequest(number, HEAD_A)

    def test_a_duplicated_pull_request_from_github_is_refused(self):
        with self.assertRaisesRegex(AutoDispatchError, "twice"):
            plan(
                open_pull_requests=[OpenPullRequest(7, HEAD_A), OpenPullRequest(7, HEAD_B)],
                approvals=[],
            )

    def test_a_malformed_stored_approval_is_refused(self):
        for row in (
            {"pr_number": 7, "head_sha": "abc", "state": "pending"},
            {"pr_number": 0, "head_sha": HEAD_A, "state": "pending"},
            {"pr_number": 7, "head_sha": HEAD_A},
            {"pr_number": 7, "head_sha": HEAD_A, "state": 5},
        ):
            with self.subTest(row=row), self.assertRaisesRegex(AutoDispatchError, "not exact"):
                plan(open_pull_requests=[], approvals=[row])

    def test_an_unknown_state_is_neither_active_nor_settled(self):
        # A state the planner does not understand must not be read as "already
        # ran"; the current head is approved, and nothing is revoked blindly.
        actions = plan(
            open_pull_requests=[OpenPullRequest(7, HEAD_A)],
            approvals=[approval(7, HEAD_A, "some-future-state")],
        )
        self.assertEqual(
            actions, (Action("approve", 7, HEAD_A, "new pull request head"),)
        )


if __name__ == "__main__":
    unittest.main()
