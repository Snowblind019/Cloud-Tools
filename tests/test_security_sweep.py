"""Tests for the Lab Sweep fixes from the security review: the account check and keep re-check in teardown, scan
errors that used to be skipped quietly, and the page's filter-aware ticking.

Run from the repo root:  python3 tests/test_security_sweep.py (or every test file with
python3 -m unittest discover -s tests)
"""
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_tools  # noqa: E402

from awskit import sweep  # noqa: E402
from awskit.common import CONFIG_FILE, load_config, save_config  # noqa: E402

mock_aws = test_tools.mock_aws
boto3 = getattr(test_tools, "boto3", None)

try:
    import gi
    gi.require_version("Gtk", "4.0")
    from awskit import sweep_page
except (ImportError, ValueError):  # pragma: no cover
    sweep_page = None


def set_config(**values):
    cfg = load_config()
    cfg.update(values)
    assert save_config(cfg)


def forget_config():
    try:
        CONFIG_FILE.unlink()
    except FileNotFoundError:
        pass


class MotoCase(unittest.TestCase):
    """An EC2 instance named lab-box and an idle Elastic IP in a fake account."""

    def setUp(self):
        forget_config()
        self.mock = mock_aws()
        self.mock.start()
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
        self.instance = ec2.run_instances(
            ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t3.micro",
            TagSpecifications=[{"ResourceType": "instance", "Tags": [
                {"Key": "Name", "Value": "lab-box"}]}])["Instances"][0]["InstanceId"]
        self.eip = ec2.allocate_address(Domain="vpc")["AllocationId"]
        self.account = boto3.client("sts", region_name="us-east-1").get_caller_identity()["Account"]

    def tearDown(self):
        self.mock.stop()
        forget_config()

    def scan(self):
        items, _ = sweep.scan([None], regions=["us-east-1"], kinds=["ec2_instance", "elastic_ip"])
        self.assertEqual({i.id for i in items}, {self.instance, self.eip})
        return items

    def instance_state(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        res = ec2.describe_instances(InstanceIds=[self.instance])["Reservations"]
        return res[0]["Instances"][0]["State"]["Name"]

    def eip_exists(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        return any(a.get("AllocationId") == self.eip for a in ec2.describe_addresses()["Addresses"])


@unittest.skipIf(mock_aws is None, "moto not installed")
class TeardownAccountTests(MotoCase):
    def test_skips_items_when_profile_points_at_another_account(self):
        items = self.scan()
        for it in items:
            it.account = "999999999999"  # what the scan saw before the profile was changed
        results = sweep.teardown(items)
        self.assertEqual([ok for _, ok, _ in results], [False, False])
        for _, _, msg in results:
            self.assertIn(f"profile default now points at account {self.account}, "
                          "not 999999999999", msg)
            self.assertIn("Scan again", msg)
        self.assertEqual(self.instance_state(), "running")
        self.assertTrue(self.eip_exists())

    def test_skips_items_with_no_account(self):
        items = self.scan()
        for it in items:
            it.account = ""
        results = sweep.teardown(items)
        self.assertFalse(any(ok for _, ok, _ in results))
        self.assertTrue(all("no account was recorded" in msg for _, _, msg in results))
        self.assertEqual(self.instance_state(), "running")

    def test_same_account_still_deletes(self):
        results = sweep.teardown(self.scan())
        self.assertEqual([msg for _, ok, msg in results if not ok], [])
        self.assertIn(self.instance_state(), ("shutting-down", "terminated"))
        self.assertFalse(self.eip_exists())


@unittest.skipIf(mock_aws is None, "moto not installed")
class TeardownKeepRecheckTests(MotoCase):
    def test_keep_list_added_after_scan_is_honored(self):
        items = self.scan()
        self.assertFalse(any(i.kept for i in items))
        set_config(keep=[self.instance])
        results = {it.id: (ok, msg) for it, ok, msg in sweep.teardown(items)}
        self.assertEqual(results[self.instance], (False, "Kept (keep list or keep tag)"))
        self.assertTrue(results[self.eip][0])
        self.assertEqual(self.instance_state(), "running")
        self.assertTrue(next(i for i in items if i.id == self.instance).kept)

    def test_keep_tag_changed_after_scan_is_honored(self):
        items = self.scan()
        set_config(keep_tag="Name")  # lab-box has a Name tag, the Elastic IP doesn't
        results = {it.id: ok for it, ok, _ in sweep.teardown(items)}
        self.assertEqual(results, {self.instance: False, self.eip: True})
        self.assertEqual(self.instance_state(), "running")

    def test_dry_run_rechecks_too(self):
        items = self.scan()
        set_config(keep=["lab-box"])
        dry = {it.id: msg for it, _, msg in sweep.teardown(items, dry_run=True)}
        self.assertEqual(dry[self.instance], "Kept (keep list or keep tag)")
        self.assertEqual(dry[self.eip], "Would delete")

    def test_keep_list_arn_is_honored_by_scan_and_teardown(self):
        arn = f"arn:aws:ec2:us-east-1:{self.account}:instance/{self.instance}"
        set_config(keep=[arn])
        scanned = {i.id: i.kept for i in self.scan()}
        self.assertEqual(scanned, {self.instance: True, self.eip: False})
        set_config(keep=[])
        items = self.scan()
        set_config(keep=[arn])  # kept by its ARN after the scan
        results = {it.id: (ok, msg) for it, ok, msg in sweep.teardown(items)}
        self.assertEqual(results[self.instance], (False, "Kept (keep list or keep tag)"))
        self.assertTrue(results[self.eip][0])
        self.assertEqual(self.instance_state(), "running")


class ApplyKeepTests(unittest.TestCase):
    def tearDown(self):
        forget_config()

    def test_apply_keep_works_both_ways(self):
        a = sweep.Item("ec2_instance", "i-aaa", tags={"team": "x"})
        b = sweep.Item("elastic_ip", "eipalloc-bbb")
        set_config(keep=["i-aaa"], keep_tag="")
        sweep.apply_keep([a, b])
        self.assertEqual((a.kept, b.kept), (True, False))
        set_config(keep=[], keep_tag="team")
        sweep.apply_keep([a, b])
        self.assertEqual((a.kept, b.kept), (True, False))
        set_config(keep=[], keep_tag="other")
        sweep.apply_keep([a, b])
        self.assertEqual((a.kept, b.kept), (False, False))

    def test_keep_list_takes_arns(self):
        # Settings says the keep list takes IDs, ARNs or names. Most items are listed by ID,
        # so an ARN used to keep nothing and the item could still be ticked and deleted.
        acct = "111122223333"
        key = sweep.Item("kms_key", "1234abcd-12ab-34cd-56ef-1234567890ab", "lab-key")
        aliased = sweep.Item("kms_key", "0b1c2d3e-12ab-34cd-56ef-1234567890ab", "prod-key")
        db = sweep.Item("rds_instance", "lab-db", "lab-db")
        bucket = sweep.Item("s3_bucket", "lab.data-bucket", "lab.data-bucket")
        snap = sweep.Item("ebs_snapshot", "snap-0123456789abcdef0")
        ca = sweep.Item("private_ca", f"arn:aws:acm-pca:us-east-1:{acct}:certificate-authority/"
                        "0f1e2d3c-1111-2222-3333-444455556666", "lab CA")
        other = sweep.Item("ec2_instance", "i-0abc1234def567890", "lab-box")
        set_config(keep_tag="", keep=[
            f"arn:aws:kms:us-east-1:{acct}:key/{key.id}",
            f"arn:aws:kms:us-east-1:{acct}:alias/prod-key",
            f"arn:aws:rds:us-east-1:{acct}:db:lab-db",
            "arn:aws:s3:::lab.data-bucket",
            "arn:aws:ec2:us-east-1::snapshot/snap-0123456789abcdef0",
            "0f1e2d3c-1111-2222-3333-444455556666",     # the CA's ID, the end of its ARN
            "arn:aws:ec2:us-east-1:111122223333:instance/i-0ffffffffffffffff"])
        items = [key, aliased, db, bucket, snap, ca, other]
        sweep.apply_keep(items)
        self.assertEqual([i.kept for i in items], [True] * 6 + [False])


@unittest.skipIf(mock_aws is None, "moto not installed")
class ScanWarningTests(unittest.TestCase):
    def setUp(self):
        forget_config()
        self.mock = mock_aws()
        self.mock.start()

    def tearDown(self):
        self.mock.stop()
        forget_config()

    @staticmethod
    def client_error(code, msg="nope"):
        from botocore.exceptions import ClientError
        return ClientError({"Error": {"Code": code, "Message": msg}}, "Describe")

    def scan_with(self, failures, regions=("us-east-1", "us-west-2")):
        """failures maps kind key to the exception its scan raises."""
        with mock.patch.multiple(sweep.KINDS["nat_gateway"], scan=mock.DEFAULT), \
                mock.patch.multiple(sweep.KINDS["vpn_connection"], scan=mock.DEFAULT), \
                mock.patch.multiple(sweep.KINDS["elastic_ip"], scan=mock.DEFAULT):
            for key, exc in failures.items():
                sweep.KINDS[key].scan.side_effect = exc
            return sweep.scan([None], regions=list(regions), kinds=list(failures))

    def test_unreachable_and_rejected_checks_become_warnings(self):
        from botocore.exceptions import EndpointConnectionError
        items, warnings = self.scan_with({
            "nat_gateway": EndpointConnectionError(endpoint_url="https://ec2.example"),
            "vpn_connection": self.client_error("UnrecognizedClientException"),
            "elastic_ip": self.client_error("AuthFailure", "AWS was not able to validate"),
        })
        self.assertEqual(items, [])
        text = "\n".join(warnings)
        self.assertIn("default: couldn't check NAT gateway in us-east-1, us-west-2. "
                      "Can't reach AWS.", text)
        self.assertIn("couldn't check Site-to-site VPN in us-east-1, us-west-2. "
                      "AWS doesn't recognize these credentials.", text)
        self.assertIn("couldn't check Elastic IP in us-east-1, us-west-2. AuthFailure", text)
        self.assertIn("take it out of the region list", text)
        self.assertEqual(len(warnings), 3)  # grouped, not one per region

    def test_service_not_offered_stays_quiet(self):
        items, warnings = self.scan_with({
            "nat_gateway": self.client_error("OptInRequired"),
            "vpn_connection": self.client_error("SubscriptionRequiredException"),
        })
        self.assertEqual((items, warnings), ([], []))

    def test_daily_check_says_it_couldnt_run(self):
        from awskit import cli
        from botocore.exceptions import EndpointConnectionError
        items, warnings = self.scan_with(
            {"nat_gateway": EndpointConnectionError(endpoint_url="https://ec2.example")})
        with mock.patch.object(cli, "notify") as notify, \
                mock.patch("sys.stderr"), mock.patch("sys.stdout"):
            rc = cli.sweep_notify(items, warnings, [None])
        self.assertEqual(rc, 1)
        title, body = notify.call_args.args[:2]
        self.assertEqual(title, "Lab sweep couldn't run")
        self.assertIn("couldn't check NAT gateway", body)

    def test_daily_check_mentions_failed_checks_next_to_findings(self):
        from awskit import cli
        cheap = sweep.Item("ebs_volume", "vol-1", "", "available", "1 GB", 0.08)
        pricey = sweep.Item("nat_gateway", "nat-1", "", "available", "", 32.0)
        warnings = ["default: couldn't check VPN in us-east-1. Can't reach AWS."]
        with mock.patch.object(cli, "notify") as notify, \
                mock.patch("sys.stderr"), mock.patch("sys.stdout"):
            rc = cli.sweep_notify([cheap], warnings, [None])     # under the threshold
        self.assertEqual(rc, 1)
        self.assertEqual(notify.call_args.args[0], "Lab sweep: some checks couldn't run")
        with mock.patch.object(cli, "notify") as notify, \
                mock.patch("sys.stderr"), mock.patch("sys.stdout"):
            cli.sweep_notify([pricey], warnings, [None])
        self.assertIn("1 check(s) couldn't run", notify.call_args.args[1])


# ---------------------------------------------------------------- page, without a display

class FakeWidget:
    def __init__(self):
        self.sensitive = True
        self.text = ""

    def set_sensitive(self, value):
        self.sensitive = value

    def set_text(self, text):
        self.text = text


class FakeRow:
    def __init__(self, item, checkable=True):
        self.obj = item
        self.checked = False
        self.checkable = checkable
        self.data = item.row()


class FakeTable:
    def __init__(self, rows, hidden=()):
        self.rows = rows
        self.hidden = list(hidden)

    def items(self):
        return list(self.rows)

    def visible_items(self):
        return [r for r in self.rows if not any(r is h for h in self.hidden)]

    def checked(self):
        return [r for r in self.rows if r.checked]


class RowTable(FakeTable):
    """A FakeTable that set_rows fills the way the real one does."""

    def set_rows(self, rows, objs=None, checkable=None):
        self.rows = []
        for n, data in enumerate(rows):
            r = FakeRow(objs[n], checkable[n] if checkable else True)
            r.data = data
            self.rows.append(r)

    def clear(self, placeholder=None):
        self.rows = []
        self.placeholder = placeholder

    def refresh_rows(self):
        pass


if sweep_page is not None:
    class FakePage:
        P = sweep_page.SweepPage
        tick_all_deletable = P.tick_all_deletable
        ticked_rows = P.ticked_rows
        update_selection = P.update_selection
        plan_lines = P.plan_lines
        teardown = P.teardown
        run_teardown = P.run_teardown
        scan = P.scan
        set_job = P.set_job
        keep_rules_changed = P.keep_rules_changed
        teardown_done = teardown_failed = scan_done = failed = None  # never called here

        def __init__(self, rows, hidden=()):
            self.table = FakeTable(rows, hidden)
            self.items = [r.obj for r in rows]
            self.job = None
            self.win = None
            self.cancel = None
            self.delete_btn, self.scan_btn, self.spend_btn = FakeWidget(), FakeWidget(), FakeWidget()
            self.sel_label = FakeWidget()
            self.show_items = mock.Mock()

    class RedrawPage(FakePage):
        """The page with its real table drawing, teardown result and Keep ticked."""
        P = sweep_page.SweepPage
        show_items = P.show_items
        item_row = P.item_row
        teardown_done = P.teardown_done
        keep_ticked = P.keep_ticked
        scan_done = P.scan_done
        export = P.export
        EXPORT_COLS = P.EXPORT_COLS

        def __init__(self, items):
            super().__init__([])
            del self.show_items  # the real one, from the class
            self.table = RowTable([])
            self.items, self.warnings = list(items), []
            self.outcomes = {}
            self.summary, self.detail = FakeWidget(), FakeWidget()
            self.status = mock.Mock()
            self.cancel = threading.Event()
            self.show_items()

        def row_for(self, item):
            return next(r for r in self.table.items() if r.obj is item)


@unittest.skipIf(sweep_page is None, "GTK 4 not installed")
class SweepPageTests(unittest.TestCase):
    def setUp(self):
        forget_config()
        self.a = sweep.Item("nat_gateway", "nat-a", region="us-east-1", monthly=32.85)
        self.b = sweep.Item("nat_gateway", "nat-b", region="us-east-1", monthly=32.85)
        self.kept = sweep.Item("nat_gateway", "nat-kept", region="us-east-1", kept=True)
        self.manual = sweep.Item("eks_cluster", "lab", region="us-east-1", can_delete=False)
        self.rows = [FakeRow(self.a), FakeRow(self.b), FakeRow(self.kept, checkable=False),
                     FakeRow(self.manual, checkable=False)]

    def tearDown(self):
        forget_config()

    def test_tick_everything_only_ticks_rows_the_filter_shows(self):
        page = FakePage(self.rows, hidden=[self.rows[1]])
        page.tick_all_deletable()
        self.assertEqual([r.checked for r in self.rows], [True, False, False, False])
        self.assertTrue(page.delete_btn.sensitive)
        self.assertNotIn("hidden", page.sel_label.text)

    def test_confirm_says_how_many_ticked_rows_are_hidden(self):
        page = FakePage(self.rows, hidden=[self.rows[1]])
        self.rows[0].checked = self.rows[1].checked = True  # b was ticked before filtering
        page.update_selection()
        self.assertIn("1 hidden by the filter", page.sel_label.text)
        with mock.patch.object(sweep_page, "ConfirmDeleteDialog") as dialog:
            page.teardown()
        _, heading, lines, _ = dialog.call_args.args
        self.assertIn("Delete 2 item(s)", heading)
        self.assertIn("1 of them are hidden by the filter", heading)
        marked = [line for line in lines if "(hidden by the filter)" in line]
        self.assertEqual(len(marked), 1)
        self.assertIn("nat-b", marked[0])

    def test_delete_and_scan_stay_off_while_teardown_runs(self):
        page = FakePage(self.rows)
        with mock.patch.object(sweep_page, "run_bg") as run_bg, \
                mock.patch.object(sweep_page, "on_main"):
            page.status = mock.Mock()
            page.new_cancel = mock.Mock(return_value="teardown-cancel")
            page.run_teardown([self.a])
            self.assertEqual(page.job, "teardown")
            self.assertEqual(run_bg.call_count, 1)
            self.assertFalse(page.scan_btn.sensitive)
            self.assertFalse(page.spend_btn.sensitive)

            # Ticking a row mid-teardown used to switch Delete back on.
            self.rows[1].checked = True
            page.update_selection()
            self.assertFalse(page.delete_btn.sensitive)

            # Neither a second teardown nor a scan can start, so Stop keeps the
            # teardown's cancel handle.
            page.new_cancel.reset_mock()
            with mock.patch.object(sweep_page, "ConfirmDeleteDialog") as dialog:
                page.teardown()
            dialog.assert_not_called()
            page.run_teardown([self.b])
            page.scan()
            self.assertEqual(run_bg.call_count, 1)
            page.new_cancel.assert_not_called()

        page.set_job(None)
        self.assertTrue(page.delete_btn.sensitive)
        self.assertTrue(page.scan_btn.sensitive)

    def test_saving_settings_reapplies_keep_rules(self):
        page = FakePage(self.rows)
        set_config(keep=["nat-a"])
        page.keep_rules_changed()
        self.assertTrue(self.a.kept)
        self.assertFalse(self.kept.kept)  # no longer on the keep list or tagged
        page.show_items.assert_called_once()

    def test_deleted_rows_stay_deleted_when_the_table_is_redrawn(self):
        # Keep ticked (or saving Settings) redraws the table from the scan. Deleted rows
        # used to come back as "can delete", tickable, so they could be deleted again.
        c = sweep.Item("nat_gateway", "nat-c", region="us-east-1", monthly=32.85)
        page = RedrawPage([self.a, self.b, c])
        for it in (self.a, self.b):
            page.row_for(it).checked = True
        page.teardown_done([(self.a, True, "Deleting"), (self.b, False, "Throttling")])
        page.row_for(c).checked = True
        page.keep_ticked()
        self.assertTrue(c.kept)
        a, b = page.row_for(self.a), page.row_for(self.b)
        self.assertEqual((a.data["action"], a.checkable, a.data["_dim"]), ("deleted", False, True))
        self.assertEqual((b.data["action"], b.checkable), ("failed", True))
        self.assertEqual(page.row_for(c).data["action"], "kept")
        page.tick_all_deletable()
        self.assertEqual([r.obj for r in page.table.checked()], [self.b])
        with mock.patch.object(sweep_page, "export_rows") as export_rows:
            page.export()
        rows = export_rows.call_args.args[1]
        self.assertEqual([r["action"] for r in rows], ["deleted", "failed", "kept"])
        self.assertFalse(any(k.startswith("_") for r in rows for k in r))
        # A new scan starts over
        page.scan_done(([self.a], []))
        self.assertEqual(page.row_for(self.a).data["action"], "can delete")

    def test_a_scan_that_couldnt_run_doesnt_look_clean(self):
        # A profile that couldn't sign in used to end in "Nothing found that costs money.
        # Nice and clean." with the reason only in the notes.
        page = RedrawPage([])
        page.scan_done(([], ["lab: Sign-in for profile lab has expired. Run: aws sso login "
                             "--profile lab"]))
        self.assertEqual(page.summary.text, "Nothing found, but some checks couldn't run.")
        self.assertIn("couldn't run", page.table.placeholder)
        self.assertNotIn("clean", page.table.placeholder)
        page.scan_done(([self.kept], ["lab: no permission to list NAT gateway (us-east-1)"]))
        self.assertEqual(page.summary.text, "Nothing found, but some checks couldn't run.")
        page.scan_done(([self.a], ["lab: no permission to list NAT gateway (us-west-2)"]))
        self.assertIn("1 item(s)", page.summary.text)
        page.scan_done(([], []))
        self.assertEqual(page.summary.text, "Nothing found that costs money.")
        self.assertIn("Nice and clean", page.table.placeholder)

    def test_a_new_scan_clears_the_last_scans_notes(self):
        page = RedrawPage([])
        page.scan_done(([], ["default: couldn't check NAT gateway in us-east-1."]))
        self.assertIn("couldn't check NAT gateway", page.detail.text)
        page.scan_done(([self.a], []))
        self.assertEqual(page.detail.text, "")


if __name__ == "__main__":
    unittest.main()
