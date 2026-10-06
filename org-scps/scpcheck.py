"""Org & SCPs: your AWS Organization as a tree, which service control policies (and resource
control policies) apply where, and "would this action be blocked here, and by what?".

It reads the org live from the management account or a delegated administrator, from
Terraform state, or from a saved snapshot, and answers offline with a plain explanation.
Read-only: it only calls Describe and List APIs, and never changes anything.

The evaluation itself lives in policyeval.py. This file holds the org model, the readers,
the SCP and RCP inheritance rules, the plain-words summaries and the command line.
"""
from __future__ import annotations

import json
import re
import shlex
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import iampolicy, policyeval
from .common import (AuthError, AwsContext, color, error_code, error_text, is_access_denied,
                     paginate, table_text, write_atomic)
from .policyeval import all_of, any_of, negate

FORMAT_NAME = "awskit-org-scps"
FORMAT_VERSION = 1
DEFAULT_SNAPSHOT_NAME = "org-scps.json"

SCP = "SERVICE_CONTROL_POLICY"
RCP = "RESOURCE_CONTROL_POLICY"
POLICY_TYPES = (SCP, RCP)
SHORT = {SCP: "SCP", RCP: "RCP"}
LONG = {SCP: "service control policy", RCP: "resource control policy"}

# AWS attaches these to the root, every OU and every account when the policy type is turned
# on, and Terraform state usually doesn't show it.
FULL_ACCESS = {
    SCP: ("p-FullAWSAccess", "FullAWSAccess",
          {"Version": "2012-10-17",
           "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}),
    RCP: ("p-RCPFullAWSAccess", "RCPFullAWSAccess",
          {"Version": "2012-10-17",
           "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}]}),
}

# Services with one endpoint in us-east-1, so aws:RequestedRegion is always us-east-1 for them.
GLOBAL_SERVICES = {"iam", "organizations", "route53", "cloudfront", "support"}

EXIT_ALLOWED, EXIT_ERROR, EXIT_DENIED, EXIT_DEPENDS = 0, 1, 3, 4

MAX_INPUT_BYTES = 64 * 1024 * 1024     # a Terraform state of a big estate is a few MB
MAX_POLICY_TEXT = 64 * 1024            # SCPs and RCPs max out at 5,120 characters
MAX_NODES = 20000
MAX_POLICIES = 5000
# AWS nests OUs at most five deep, so a path is root, five OUs and an account. A deeper
# tree only comes from a damaged or made-up file; its deep nodes are put under the root.
MAX_DEPTH = 32


class ScpError(Exception):
    """Something that stops the org from being read or a test from running. The message
    says why in plain words."""


class Cancelled(ScpError):
    pass


# =================================================================== model

@dataclass
class Policy:
    id: str
    name: str
    type: str = SCP
    text: str = ""              # the policy JSON, as AWS keeps it
    description: str = ""
    aws_managed: bool = False
    draft: bool = False
    error: str = ""             # why the text couldn't be read
    doc: dict = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        if self.doc is None and self.text and not self.error:
            self.doc, self.error = parse_policy_text(self.text)
        if self.doc is not None and not self.text:
            self.text = json.dumps(self.doc, indent=2)

    @property
    def short_type(self) -> str:
        return SHORT.get(self.type, self.type)

    @property
    def display(self) -> str:
        return "the draft SCP" if self.draft else self.name


def parse_policy_text(text) -> tuple:
    """(doc, error) for a policy's JSON text."""
    if not isinstance(text, str):
        return None, "Its text isn't a string."
    if len(text) > MAX_POLICY_TEXT:
        return None, "Its text is over 64 KB, which no SCP or RCP can be."
    try:
        doc = json.loads(text)
    except RecursionError:
        return None, "Its text is nested too deeply to be a policy."
    except ValueError as exc:
        return None, f"Its text isn't valid JSON: {exc}"
    if not isinstance(doc, dict) or "Statement" not in doc:
        return None, "Its text isn't a policy with a Statement list."
    return doc, ""


@dataclass
class Node:
    id: str
    kind: str                   # root, ou or account
    name: str = ""
    parent: str = ""
    arn: str = ""
    status: str = ""
    policies: list = field(default_factory=list)    # IDs of policies attached here
    assumed: list = field(default_factory=list)     # attached by assumption (Terraform)
    guessed_parent: bool = False


@dataclass
class Org:
    id: str = ""
    arn: str = ""
    management: str = ""
    feature_set: str = "ALL"
    root: str = ""
    enabled: list = field(default_factory=list)     # policy types turned on at the root
    nodes: dict = field(default_factory=dict)
    policies: dict = field(default_factory=dict)
    source: str = ""            # aws or terraform
    label: str = ""             # the profile or file it came from
    read_at: str = ""
    notes: list = field(default_factory=list)
    saved_at: str = ""          # set when it was loaded from a snapshot
    unreadable: list = field(default_factory=list)  # policy types that couldn't be read
    unplaced: list = field(default_factory=list)    # policies whose targets couldn't be read
    unread_targets: list = field(default_factory=list)  # nodes whose policies couldn't be read

    def note(self, text):
        if text and text not in self.notes:
            self.notes.append(text)

    def node(self, node_id) -> Node:
        node = self.nodes.get(node_id)
        if node is None:
            raise ScpError(f"There's no {node_id} in this organization.")
        return node

    def enabled_type(self, ptype) -> bool:
        return ptype in self.enabled

    def _order(self, n):
        return (n.kind != "ou", n.id != self.management, n.name.lower(), n.id)

    def children(self, node_id) -> list:
        kids = [n for n in self.nodes.values() if n.parent == node_id and n.id != node_id]
        return sorted(kids, key=self._order)

    def children_map(self) -> dict:
        """{parent ID: sorted children} in one pass, for walking a big tree. children()
        looks at every node each time, which adds up to minutes for 20,000 nodes."""
        out = {}
        for n in self.nodes.values():
            if n.id != n.parent:
                out.setdefault(n.parent, []).append(n)
        for kids in out.values():
            kids.sort(key=self._order)
        return out

    def path(self, node_id) -> list:
        """The root first, down to node_id."""
        out, seen = [], set()
        cur = self.node(node_id)
        while True:
            if cur.id in seen:
                raise ScpError(f"The tree loops back on itself at {cur.id}.")
            if len(out) >= MAX_DEPTH:
                raise ScpError(f"The tree is deeper than AWS allows at {cur.id}.")
            seen.add(cur.id)
            out.append(cur)
            if cur.kind == "root" or not cur.parent:
                break
            cur = self.node(cur.parent)
        return list(reversed(out))

    def walk(self) -> list:
        """(node, depth) for every node, in tree order."""
        out = []
        if self.root not in self.nodes:
            return out
        kids = self.children_map()
        stack = [(self.nodes[self.root], 0)]
        seen = set()
        while stack:
            node, depth = stack.pop()
            if node.id in seen:
                continue
            seen.add(node.id)
            out.append((node, depth))
            for kid in reversed(kids.get(node.id, [])):
                stack.append((kid, depth + 1))
        return out

    def accounts(self) -> list:
        return [n for n, _ in self.walk() if n.kind == "account"]

    def attached(self, node_id, ptype=None) -> list:
        """[(policy, assumed)] attached right at node_id."""
        node = self.node(node_id)
        out = []
        for pid in node.policies + node.assumed:
            pol = self.policies.get(pid)
            if pol is not None and (ptype is None or pol.type == ptype):
                out.append((pol, pid in node.assumed and pid not in node.policies))
        return sorted(out, key=lambda pa: (pa[0].type, not pa[0].aws_managed, pa[0].name.lower()))

    def where(self, node_id) -> str:
        """'Root', 'OU Workloads' or 'Account lab', for column-style output."""
        node = self.nodes.get(node_id)
        if node is None:
            return node_id
        if node.kind == "root":
            return "Root"
        return ("OU " if node.kind == "ou" else "Account ") + (node.name or node.id)

    def in_words(self, node_id) -> str:
        """'the root', 'OU Workloads' or 'account lab', for the middle of a sentence."""
        node = self.nodes.get(node_id)
        if node is None:
            return node_id
        if node.kind == "root":
            return "the root"
        return ("OU " if node.kind == "ou" else "account ") + (node.name or node.id)

    def counts(self) -> dict:
        kinds = [n.kind for n in self.nodes.values()]
        return {"accounts": kinds.count("account"), "ous": kinds.count("ou"),
                "policies": len(self.policies)}

    def find(self, text, kinds=("root", "ou", "account")) -> Node:
        """A node by ID or name, case-insensitive. 'root' finds the root."""
        want = str(text or "").strip()
        if not want:
            raise ScpError("Say which account, OU or root.")
        if want.lower() == "root" and "root" in kinds and self.root in self.nodes:
            return self.nodes[self.root]
        if want in self.nodes and self.nodes[want].kind in kinds:
            return self.nodes[want]
        hits = [n for n in self.nodes.values() if n.kind in kinds and
                (n.name.lower() == want.lower() or n.id.lower() == want.lower())]
        if len(hits) == 1:
            return hits[0]
        what = "account" if kinds == ("account",) else "account, OU or root"
        if not hits:
            close = sorted(n.name or n.id for n in self.nodes.values()
                           if n.kind in kinds and want.lower() in (n.name + " " + n.id).lower())
            raise ScpError(f"No {what} called {want}." +
                           (f" Did you mean: {', '.join(close[:5])}?" if close else ""))
        raise ScpError(f"More than one {what} is called {want}: " +
                       ", ".join(f"{n.name} ({n.id})" for n in hits) + ". Use the ID.")

    def summary_line(self) -> str:
        c = self.counts()
        n_scp = sum(1 for p in self.policies.values() if p.type == SCP)
        n_rcp = sum(1 for p in self.policies.values() if p.type == RCP)
        parts = [plural(c["accounts"], "account"), plural(c["ous"], "OU"),
                 plural(n_scp, "SCP")]
        if n_rcp:
            parts.append(plural(n_rcp, "RCP"))
        return ", ".join(parts)


def plural(n, word) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _add_full_access(org, ptype) -> Policy:
    pid, name, doc = FULL_ACCESS[ptype]
    if pid not in org.policies:
        org.policies[pid] = Policy(pid, name, ptype, json.dumps(doc), aws_managed=True,
                                   description="AWS managed: allows everything")
    return org.policies[pid]


# =================================================================== snapshots

def to_dict(org: Org) -> dict:
    nodes = []
    for node, _ in org.walk():
        nodes.append({"id": node.id, "kind": node.kind, "name": node.name,
                      "parent": node.parent, "arn": node.arn, "status": node.status,
                      "policies": sorted(node.policies), "assumed_policies": sorted(node.assumed),
                      "guessed_parent": node.guessed_parent})
    return {
        "format": FORMAT_NAME,
        "format_version": FORMAT_VERSION,
        "saved_at": _now(),
        "source": org.source,
        "label": org.label,
        "read_at": org.read_at,
        "organization": {"id": org.id, "arn": org.arn, "management_account": org.management,
                         "feature_set": org.feature_set, "root": org.root,
                         "enabled_policy_types": sorted(org.enabled),
                         "unreadable_policy_types": sorted(org.unreadable),
                         "unplaced_policies": sorted(org.unplaced),
                         "unread_attachments": sorted(org.unread_targets)},
        "nodes": nodes,
        "policies": [{"id": p.id, "name": p.name, "type": p.type, "description": p.description,
                      "aws_managed": p.aws_managed, "content": p.text if p.doc is not None else "",
                      "error": p.error}
                     for p in sorted(org.policies.values(), key=lambda p: p.id) if not p.draft],
        "notes": list(org.notes),
    }


def dumps(org: Org) -> str:
    return json.dumps(to_dict(org), indent=2, ensure_ascii=False) + "\n"


def save_snapshot(org: Org, path) -> Path:
    path = Path(path).expanduser()
    write_atomic(path, dumps(org))
    return path


def _s(value, what="value") -> str:
    if value is None:
        return ""
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        raise ScpError(f"The snapshot is damaged: a {what} isn't text.")
    return str(value)


def _str_list(value, what) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ScpError(f"The snapshot is damaged: {what} isn't a list.")
    return [_s(v, what) for v in value]


def from_dict(data) -> Org:
    if not isinstance(data, dict) or data.get("format") != FORMAT_NAME:
        raise ScpError("That isn't an Org & SCPs snapshot. Save one with Save snapshot or "
                       "awskit scp save.")
    version = data.get("format_version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise ScpError("The snapshot is damaged: it has no format version.")
    if version > FORMAT_VERSION:
        raise ScpError(f"This snapshot is format version {version}, which is newer than this "
                       f"AWS Kit understands ({FORMAT_VERSION}). Update AWS Kit.")
    o = data.get("organization")
    if not isinstance(o, dict):
        raise ScpError("The snapshot is damaged: it has no organization.")
    nodes = data.get("nodes")
    policies = data.get("policies") or []
    if not isinstance(nodes, list) or not isinstance(policies, list):
        raise ScpError("The snapshot is damaged: nodes and policies have to be lists.")
    if len(nodes) > MAX_NODES or len(policies) > MAX_POLICIES:
        raise ScpError("The snapshot is bigger than any organization AWS allows.")
    org = Org(id=_s(o.get("id"), "organization ID"), arn=_s(o.get("arn"), "ARN"),
              management=_s(o.get("management_account"), "account ID"),
              feature_set=_s(o.get("feature_set"), "feature set") or "ALL",
              root=_s(o.get("root"), "root ID"),
              enabled=[t for t in _str_list(o.get("enabled_policy_types"), "policy types")
                       if t in POLICY_TYPES],
              unreadable=[t for t in _str_list(o.get("unreadable_policy_types"), "policy types")
                          if t in POLICY_TYPES],
              unplaced=_str_list(o.get("unplaced_policies"), "policy IDs"),
              unread_targets=_str_list(o.get("unread_attachments"), "IDs"),
              source=_s(data.get("source"), "source"), label=_s(data.get("label"), "label"),
              read_at=_s(data.get("read_at"), "time"), saved_at=_s(data.get("saved_at"), "time"),
              notes=_str_list(data.get("notes"), "notes"))
    for p in policies:
        if not isinstance(p, dict):
            raise ScpError("The snapshot is damaged: a policy isn't an object.")
        pid = _s(p.get("id"), "policy ID")
        if not pid:
            raise ScpError("The snapshot is damaged: a policy has no ID.")
        ptype = _s(p.get("type"), "policy type") or SCP
        if ptype not in POLICY_TYPES:
            continue
        content = _s(p.get("content"), "policy text")
        org.policies[pid] = Policy(pid, _s(p.get("name"), "policy name") or pid, ptype, content,
                                   _s(p.get("description"), "description"),
                                   bool(p.get("aws_managed")),
                                   error=_s(p.get("error"), "error") or
                                   ("" if content else "Its text wasn't saved."))
    for n in nodes:
        if not isinstance(n, dict):
            raise ScpError("The snapshot is damaged: a node isn't an object.")
        nid, kind = _s(n.get("id"), "ID"), _s(n.get("kind"), "kind")
        if not nid or kind not in ("root", "ou", "account"):
            raise ScpError("The snapshot is damaged: a node has no ID or an unknown kind.")
        org.nodes[nid] = Node(nid, kind, _s(n.get("name"), "name"), _s(n.get("parent"), "parent"),
                              _s(n.get("arn"), "ARN"), _s(n.get("status"), "status"),
                              [x for x in _str_list(n.get("policies"), "policies")
                               if x in org.policies],
                              [x for x in _str_list(n.get("assumed_policies"), "policies")
                               if x in org.policies],
                              bool(n.get("guessed_parent")))
    roots = [n for n in org.nodes.values() if n.kind == "root"]
    if len(roots) != 1:
        raise ScpError("The snapshot is damaged: it needs exactly one root.")
    org.root = roots[0].id
    roots[0].parent = ""
    _connect(org)
    return org


def _connect(org):
    """Every node has to hang off the root. Anything that doesn't (a missing parent, or a
    loop) is put right under the root, with a note."""
    stray = []
    for node in list(org.nodes.values()):
        if node.kind == "root":
            continue
        try:
            path = org.path(node.id)
            ok = path[0].id == org.root
        except ScpError:
            ok = False
        if not ok:
            stray.append(node)
            node.parent = org.root
            node.guessed_parent = True
    if stray:
        org.note(f"{plural(len(stray), 'OU or account')} couldn't be placed in the tree "
                 f"({', '.join(n.name or n.id for n in stray[:4])}), so "
                 f"{'it shows' if len(stray) == 1 else 'they show'} under the root.")


# =================================================================== reading AWS

QUIET_RCP_CODES = {"InvalidInputException", "ValidationException", "UnknownOperationException",
                   "UnsupportedAPIEndpointException", "PolicyTypeNotEnabledException"}


def org_region(ctx) -> str:
    """Organizations has one endpoint per partition."""
    region = ctx.default_region or ""
    if region.startswith("us-gov-"):
        return "us-gov-west-1"
    if region.startswith("cn-"):
        return "cn-northwest-1"
    return "us-east-1"


def read_live(profile=None, progress=None, cancel=None, workers=4, attachments="auto") -> Org:
    """Read the org from AWS. Needs the management account or a delegated administrator.
    attachments: "auto" picks list_targets_for_policy or list_policies_for_target,
    whichever needs fewer calls; "by-policy" and "by-target" force one."""
    ctx = AwsContext(profile)
    who = f"Profile {profile}" if profile else "These credentials"
    region = org_region(ctx)
    state = {"done": 0, "total": 3}

    def check():
        if cancel is not None and cancel.is_set():
            raise Cancelled("Stopped before the whole organization was read.")

    def step(text, add=0):
        state["total"] += add
        state["done"] += 1
        if progress:
            progress(state["done"], state["total"], text)

    def client():
        return ctx.client("organizations", region)

    check()
    try:
        d = client().describe_organization()["Organization"]
    except Exception as exc:  # noqa: BLE001 - boto raises many types here
        if error_code(exc) == "AWSOrganizationsNotInUseException":
            raise ScpError("This account isn't in an organization, so there are no SCPs to "
                           "show.") from exc
        if is_access_denied(exc):
            raise ScpError(f"{who} can't read AWS Organizations (DescribeOrganization was "
                           "denied). Use a profile for the management account or a delegated "
                           "administrator, with organizations:Describe* and "
                           "organizations:List*.") from exc
        raise ScpError(f"Couldn't read the organization: {error_text(exc, profile)}") from exc
    step("Read the organization")
    org = Org(id=d.get("Id", ""), arn=d.get("Arn", ""), management=d.get("MasterAccountId", ""),
              feature_set=d.get("FeatureSet", "ALL"), source="aws",
              label=f"profile {profile}" if profile else "the default credentials")

    check()
    try:
        roots = list(paginate(client(), "list_roots", "Roots"))
    except Exception as exc:  # noqa: BLE001
        if not is_access_denied(exc):
            raise ScpError(f"Couldn't list the organization's roots: "
                           f"{error_text(exc, profile)}") from exc
        try:
            me = ctx.account
        except AuthError:
            me = ""
        if me and org.management and me != org.management:
            raise ScpError(f"{who} is signed in to account {me}, a member account. The org "
                           "tree and its policies can only be read from the management account "
                           f"({org.management}) or a delegated administrator for AWS "
                           "Organizations. Use a profile for one of those, or open a Terraform "
                           "state or a snapshot instead.") from exc
        raise ScpError(f"{who} can't list the organization (ListRoots was denied). It needs "
                       "organizations:Describe* and organizations:List*.") from exc
    if not roots:
        raise ScpError("The organization has no root, which AWS never allows. Try again.")
    root = roots[0]
    org.root = root["Id"]
    org.enabled = sorted({t.get("Type") for t in root.get("PolicyTypes") or []
                          if t.get("Status") == "ENABLED"} & set(POLICY_TYPES))
    org.nodes[org.root] = Node(org.root, "root", root.get("Name") or "Root", "",
                               root.get("Arn", ""))
    step("Read the root")

    def denied_text(what, exc):
        if is_access_denied(exc):
            return f"{who} can't {what} (no permission). It needs organizations:List*."
        return f"Couldn't {what}: {error_text(exc, profile)}"

    def children_of(parent):
        check()
        c = client()
        try:
            ous = list(paginate(c, "list_organizational_units_for_parent",
                                "OrganizationalUnits", ParentId=parent))
            accts = list(paginate(c, "list_accounts_for_parent", "Accounts", ParentId=parent))
        except Cancelled:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ScpError(denied_text("list the OUs and accounts", exc)) from exc
        return parent, ous, accts

    pending = [org.root]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        while pending:
            check()
            futures = [pool.submit(children_of, p) for p in pending]
            state["total"] += len(pending)
            pending = []
            for fut in as_completed(futures):
                parent, ous, accts = fut.result()
                for ou in ous:
                    org.nodes[ou["Id"]] = Node(ou["Id"], "ou", ou.get("Name", ""), parent,
                                               ou.get("Arn", ""))
                    pending.append(ou["Id"])
                for a in accts:
                    org.nodes[a["Id"]] = Node(a["Id"], "account", a.get("Name", ""), parent,
                                              a.get("Arn", ""), a.get("Status", ""))
                step("Listing OUs and accounts")
                if len(org.nodes) > MAX_NODES:
                    raise ScpError("This organization is bigger than AWS Kit reads.")

    if org.feature_set != "ALL":
        org.note("This organization only has consolidated billing turned on, so it can't use "
                 "SCPs or RCPs.")
    elif SCP not in org.enabled:
        org.note("SCPs aren't turned on for this organization, so they don't limit anything.")
    types = [t for t in POLICY_TYPES if t in org.enabled]

    listed = []
    for ptype in types:
        check()
        try:
            got = list(paginate(client(), "list_policies", "Policies", Filter=ptype))
        except Cancelled:
            raise
        except Exception as exc:  # noqa: BLE001
            if ptype == RCP and (error_code(exc) in QUIET_RCP_CODES or
                                 type(exc).__name__ == "ParamValidationError"):
                org.unreadable.append(RCP)
                org.note("Couldn't list the resource control policies, so RCPs weren't checked. "
                         "Older AWS SDKs and some partitions don't know about them yet "
                         f"({error_text(exc, profile)}).")
                continue
            raise ScpError(denied_text(f"list the {LONG[ptype]}s", exc)) from exc
        listed += [(ptype, p) for p in got]
        step(f"Listed {SHORT[ptype]}s")
    if len(listed) > MAX_POLICIES:
        raise ScpError("This organization has more policies than AWS Kit reads.")

    def describe(item):
        check()
        ptype, p = item
        try:
            got = client().describe_policy(PolicyId=p["Id"])["Policy"]
            text, err = got.get("Content", ""), ""
        except Cancelled:
            raise
        except Exception as exc:  # noqa: BLE001
            text = ""
            err = ("Its text couldn't be read: no permission for "
                   "organizations:DescribePolicy." if is_access_denied(exc)
                   else f"Its text couldn't be read: {error_text(exc, profile)}")
        return Policy(p["Id"], p.get("Name", p["Id"]), ptype, text, p.get("Description", ""),
                      bool(p.get("AwsManaged")), error=err)

    state["total"] += len(listed)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for fut in as_completed([pool.submit(describe, item) for item in listed]):
            pol = fut.result()
            org.policies[pol.id] = pol
            step(f"Read {pol.name}")
    unread = sorted(p.name for p in org.policies.values() if p.error)
    if unread:
        org.note(f"Couldn't read the text of {', '.join(unread[:5])}"
                 f"{' and more' if len(unread) > 5 else ''}, so tests that reach "
                 f"{'it' if len(unread) == 1 else 'them'} say Depends.")

    targets = list(org.nodes)
    by_policy = attachments == "by-policy" or (
        attachments == "auto" and len(org.policies) <= len(targets) * max(len(types), 1))
    failed = []

    def targets_for(pid):
        check()
        try:
            return pid, [t["TargetId"] for t in paginate(client(), "list_targets_for_policy",
                                                         "Targets", PolicyId=pid)]
        except Cancelled:
            raise
        except Exception as exc:  # noqa: BLE001
            failed.append(error_text(exc, profile))
            return pid, None

    def policies_for(job):
        check()
        target, ptype = job
        try:
            return target, [p["Id"] for p in paginate(client(), "list_policies_for_target",
                                                       "Policies", TargetId=target,
                                                       Filter=ptype)]
        except Cancelled:
            raise
        except Exception as exc:  # noqa: BLE001
            failed.append(error_text(exc, profile))
            return target, None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        if by_policy:
            jobs = [pool.submit(targets_for, pid) for pid in sorted(org.policies)]
        else:
            jobs = [pool.submit(policies_for, (t, ptype)) for t in targets
                    for ptype in types if ptype not in org.unreadable]
        state["total"] += len(jobs)
        for fut in as_completed(jobs):
            key, got = fut.result()
            step("Reading where policies are attached")
            if got is None:
                lost = org.unplaced if by_policy else org.unread_targets
                if key not in lost:
                    lost.append(key)
                continue
            if by_policy:
                for target in got:
                    if target in org.nodes and key not in org.nodes[target].policies:
                        org.nodes[target].policies.append(key)
            else:
                for pid in got:
                    if pid in org.policies and pid not in org.nodes[key].policies:
                        org.nodes[key].policies.append(pid)
    if org.unplaced:
        names = sorted(org.policies[p].name for p in org.unplaced if p in org.policies)
        org.note(f"Couldn't read where {join(names, 'and')} "
                 f"{'is' if len(names) == 1 else 'are'} attached ({failed[0]}), so a test "
                 f"{'it' if len(names) == 1 else 'one of them'} could block says Depends.")
    if org.unread_targets:
        org.note(f"Couldn't read which policies are attached to "
                 f"{join(sorted(org.where(t) for t in org.unread_targets), 'and')} "
                 f"({failed[0]}), so tests that pass through there say Depends.")
    for node in org.nodes.values():
        node.policies.sort()
    org.read_at = _now()
    return org


# =================================================================== reading Terraform

TF_ORG_TYPES = ("aws_organizations_organization", "aws_organizations_organizational_unit",
                "aws_organizations_account", "aws_organizations_policy",
                "aws_organizations_policy_attachment")


def from_terraform(data, label="", full_access="auto") -> Org:
    """An org from terraform show -json output (state or plan) or a raw .tfstate.

    full_access says where AWS's FullAWSAccess (and RCPFullAWSAccess) count as attached:
    "auto" assumes everywhere unless the state manages its attachments, "everywhere"
    always assumes it, and "state" only counts what the state shows."""
    from . import maptf
    try:
        resources, kind, providers = maptf.flatten(data)
        b = maptf.Builder(resources, providers, label, kind)
        b.place()
        return _org_from_terraform(b, kind, label, full_access)
    except maptf.TfError as exc:
        raise ScpError(str(exc)) from exc
    except (AttributeError, TypeError, KeyError, ValueError, IndexError) as exc:
        # A value of the wrong type somewhere in the file, like a number where a list goes.
        raise ScpError(f"That Terraform JSON couldn't be read: {type(exc).__name__} {exc}") \
            from exc


def _org_from_terraform(b, kind, label, full_access) -> Org:
    org = Org(source="terraform", label=label)
    of = {t: [r for r in b.all if r.type == t] for t in TF_ORG_TYPES}
    if not any(of[t] for t in TF_ORG_TYPES):
        raise ScpError(f"{label or 'That state'} has no AWS Organizations resources "
                       "(aws_organizations_*), so there's no org to show.")
    if kind == "plan":
        org.note("Read from a plan, so this is the org as it will be after apply.")

    def known(r, attr):
        v = b.known(r, attr) if r.mode != "data" else r.values.get(attr)
        return "" if v is None else v

    def text(r, attr, default=""):
        v = known(r, attr)
        return str(v) if isinstance(v, (str, int)) and not isinstance(v, bool) else default

    org_nodes = set()      # what references to the organization itself resolve to
    orgs = sorted(of["aws_organizations_organization"], key=lambda r: r.mode == "data")
    seen_accounts = {}
    if orgs:
        o = orgs[0]
        org.id = text(o, "id")
        org.arn = text(o, "arn")
        org.management = text(o, "master_account_id")
        org.feature_set = text(o, "feature_set") or "ALL"
        roots = o.values.get("roots") or []
        root = roots[0] if roots and isinstance(roots[0], dict) else {}
        org.root = str(root.get("id") or "")
        types = [t.get("type") for t in (root.get("policy_types") or [])
                 if isinstance(t, dict) and t.get("status") == "ENABLED"]
        if not types:
            types = [str(t) for t in (o.values.get("enabled_policy_types") or [])]
        org.enabled = sorted(set(types) & set(POLICY_TYPES))
        for r in orgs:
            org_nodes |= {x for x in (r.node, r.address, text(r, "id")) if x}
        for a in o.values.get("accounts") or []:
            if isinstance(a, dict) and a.get("id"):
                seen_accounts[str(a["id"])] = a
    else:
        org.note("The state has no aws_organizations_organization, so the root ID and which "
                 "policy types are turned on come from the other resources.")

    ous = of["aws_organizations_organizational_unit"]
    parents = [b.ref(r, "parent_id") for r in ous + of["aws_organizations_account"]]
    if not org.root:
        guess = sorted({p for p in parents if str(p).startswith("r-")})
        org.root = guess[0] if guess else "r-unknown"
    org.nodes[org.root] = Node(org.root, "root", "Root")

    def parent_of(r):
        p = b.ref(r, "parent_id")
        if not p or p in org_nodes:
            return org.root
        return p

    for r in ous:
        if r.mode == "data":
            continue
        nid = text(r, "id") or r.node
        org.nodes[nid] = Node(nid, "ou", text(r, "name") or r.name, parent_of(r), text(r, "arn"))
    for r in of["aws_organizations_account"]:
        if r.mode == "data":
            continue
        nid = text(r, "id") or r.node
        org.nodes[nid] = Node(nid, "account", text(r, "name") or r.name, parent_of(r),
                              text(r, "arn"), text(r, "status"))
    guessed = []
    for aid, a in sorted(seen_accounts.items()):
        if aid not in org.nodes:
            org.nodes[aid] = Node(aid, "account", str(a.get("name") or aid), org.root,
                                  str(a.get("arn") or ""), str(a.get("status") or ""),
                                  guessed_parent=True)
            guessed.append(str(a.get("name") or aid))
    if org.management and org.management not in org.nodes:
        org.nodes[org.management] = Node(org.management, "account", "management account",
                                         org.root, guessed_parent=True)
        guessed.append("the management account")
    if guessed:
        org.note(f"The state doesn't say which OU {join(guessed, 'and')} "
                 f"{'is' if len(guessed) == 1 else 'are'} in, so "
                 f"{'it shows' if len(guessed) == 1 else 'they show'} under the root.")
    for node in org.nodes.values():
        if node.kind != "root" and node.parent not in org.nodes:
            node.guessed_parent = True
    _connect(org)

    other_types, other_ids = set(), set()
    for r in sorted(of["aws_organizations_policy"], key=lambda r: r.mode == "data"):
        ptype = text(r, "type") or SCP
        pid = text(r, "id") or r.node
        if ptype not in POLICY_TYPES:
            other_types.add(ptype)
            other_ids |= {x for x in (pid, r.node, r.address) if x}
            continue
        if pid in org.policies:
            continue
        content = known(r, "content")
        org.policies[pid] = Policy(pid, text(r, "name") or r.name, ptype,
                                   content if isinstance(content, str) else "",
                                   text(r, "description"),
                                   error="" if isinstance(content, str) and content else
                                   "Its text isn't known yet (it's set at apply).")
    if other_types:
        org.note("Other policy types in the state aren't checked: " +
                 ", ".join(sorted(t.replace("_", " ").lower() for t in other_types)) + ".")

    managed_full = {t: set() for t in POLICY_TYPES}
    missing_text = set()
    for r in of["aws_organizations_policy_attachment"]:
        if r.mode == "data":
            continue
        pid, target = b.ref(r, "policy_id"), b.ref(r, "target_id")
        if not pid or not target or pid in other_ids:
            continue          # a tag, backup or other policy isn't an SCP with unknown text
        if target in org_nodes:
            target = org.root
        if target not in org.nodes:
            continue
        for ptype in POLICY_TYPES:
            if pid == FULL_ACCESS[ptype][0]:
                _add_full_access(org, ptype)
                managed_full[ptype].add(target)
        if pid not in org.policies:
            org.policies[pid] = Policy(pid, pid, SCP,
                                       error="Its text isn't in this state, so it wasn't checked.")
            missing_text.add(pid)
        if pid not in org.nodes[target].policies:
            org.nodes[target].policies.append(pid)
    if missing_text:
        org.note(f"{join(sorted(missing_text), 'and')} {'is' if len(missing_text) == 1 else 'are'}"
                 " attached in this state but defined somewhere else, so "
                 f"{'its' if len(missing_text) == 1 else 'their'} text isn't known. Tests that "
                 "reach them say Depends.")

    if not orgs:
        org.enabled = sorted({p.type for p in org.policies.values()})
    for ptype in org.enabled:
        pid, name, _doc = FULL_ACCESS[ptype]
        managed = managed_full[ptype]
        # RCPFullAWSAccess can't be detached, so only "state" leaves it out.
        if full_access == "state" or (full_access == "auto" and managed and ptype == SCP):
            if full_access == "state":
                if not managed:
                    org.note(f"{name} isn't attached anywhere in the state, and you asked to "
                             "only count what the state shows.")
                continue
            # AWS never leaves a root, OU or account without an SCP, so where the state shows
            # none at all, FullAWSAccess must still be there.
            bare = [n for n in org.nodes.values()
                    if not any(org.policies.get(x) is not None and org.policies[x].type == ptype
                               for x in n.policies)]
            for node in bare:
                node.assumed.append(pid)
            names = join([n.name or n.id for n in bare], "and")
            org.note(f"Terraform manages {name} attachments here, so it only counts as attached "
                     "where the state attaches it" +
                     (f", and where the state shows no SCP at all ({names}), since AWS always "
                      "keeps one attached." if bare else "."))
            continue
        _add_full_access(org, ptype)
        for node in org.nodes.values():
            if pid not in node.policies and pid not in node.assumed:
                node.assumed.append(pid)
        org.note(f"{name} is assumed to be attached to the root and every OU and account. AWS "
                 f"attaches it when {SHORT[ptype]}s are turned on, and Terraform state usually "
                 "doesn't show it.")
    org.notes.sort(key=lambda n: "FullAWSAccess is assumed" not in n)
    if not org.enabled and orgs:
        org.note("SCPs aren't turned on in this state (enabled_policy_types), so they don't "
                 "limit anything.")
    for node in org.nodes.values():
        node.policies.sort()
        node.assumed.sort()
    org.read_at = _now()
    return org


# =================================================================== loading files

def join(items, word="and") -> str:
    return policyeval.join_words(items, word, limit=6)


def read_json_file(path) -> object:
    p = Path(path).expanduser()
    try:
        size = p.stat().st_size
    except OSError as exc:
        raise ScpError(f"Couldn't read {p}: {exc.strerror or exc}") from exc
    if size > MAX_INPUT_BYTES:
        raise ScpError(f"{p.name} is over 64 MB, bigger than any state or snapshot this "
                       "reads.")
    try:
        with p.open("rb") as f:
            # Read no more than the limit: a pipe or device has no size to check first.
            raw = f.read(MAX_INPUT_BYTES + 1)
    except OSError as exc:
        raise ScpError(f"Couldn't read {p}: {exc.strerror or exc}") from exc
    if len(raw) > MAX_INPUT_BYTES:
        raise ScpError(f"{p.name} is over 64 MB, bigger than any state or snapshot this "
                       "reads.")
    if raw.lstrip()[:1] != b"{":
        raise ScpError(f"{p.name} isn't JSON. Open a snapshot, a .tfstate file or the output of "
                       "terraform show -json. A saved binary plan needs terraform show -json "
                       "first.")
    try:
        return json.loads(raw.decode("utf-8-sig"))
    except RecursionError:
        raise ScpError(f"{p.name} is nested too deeply to be a state or a snapshot.") from None
    except (ValueError, UnicodeDecodeError) as exc:
        raise ScpError(f"{p.name} isn't valid JSON: {exc}") from exc


def from_data(data, label="", full_access="auto") -> Org:
    """A snapshot or Terraform JSON, told apart by what's in it."""
    if isinstance(data, dict) and data.get("format") == FORMAT_NAME:
        return from_dict(data)
    if isinstance(data, dict) and data.get("format") == "awskit-cloudmap":
        raise ScpError("That's a Cloud Map snapshot. It has the org tree but not the policy "
                       "text, so it can't be tested. Open the Terraform state, or read the org "
                       "from AWS.")
    return from_terraform(data, label, full_access)


def load_file(path, full_access="auto") -> Org:
    p = Path(path).expanduser()
    if p.is_dir():
        raise ScpError(f"{p} is a folder. Reading a Terraform folder runs terraform show "
                       "there, so use the Folder button or give the folder on the command line.")
    return from_data(read_json_file(p), p.name, full_access)


def load_folder(folder, profile=None, full_access="auto") -> Org:
    """terraform show -json in a folder. That runs the folder's providers, so the window
    asks first (widgets.confirm_terraform)."""
    from . import tfplan
    folder = Path(folder).expanduser()
    if not folder.is_dir():
        raise ScpError(f"{folder} isn't a folder.")
    try:
        data = tfplan.show_state(str(folder), profile=profile)
    except tfplan.PlanError as exc:
        raise ScpError(str(exc)) from exc
    if not data.get("values"):
        raise ScpError(f"{folder.name} has no Terraform state yet. Run terraform apply there "
                       "first, or open a state file.")
    return from_terraform(data, folder.name, full_access)


# =================================================================== the request

def parse_context(items) -> dict:
    """key=value pairs (a list, or one string split like a shell would) into a context.
    A key given twice gets both values. !key means the key isn't set."""
    if isinstance(items, str):
        try:
            items = shlex.split(items)
        except ValueError as exc:
            raise ScpError(f"Couldn't read the context: {exc}.") from exc
    out = {}
    for item in items or []:
        item = str(item).strip()
        if not item:
            continue
        if item.startswith("!"):
            key = item[1:].strip()
            if ":" not in key:
                raise ScpError(f"{item} isn't a context key. Write !key, like "
                               "!aws:MultiFactorAuthPresent.")
            out[key] = policyeval.ABSENT
            continue
        if "=" not in item:
            raise ScpError(f"{item} isn't key=value. Write context like "
                           "aws:PrincipalTag/team=data.")
        key, value = item.split("=", 1)
        key = key.strip()
        if ":" not in key or not re.fullmatch(r"[\w:/.@+=,-]+", key):
            raise ScpError(f"{key} isn't a context key. Keys look like aws:SourceIp or "
                           "aws:PrincipalTag/team.")
        prev = out.get(key)
        if isinstance(prev, list):
            prev.append(value)
        else:
            out[key] = [value]
    return out


def parse_principal(arn) -> dict:
    """What a principal ARN means for the request context."""
    arn = str(arn or "").strip()
    out = {"given": arn, "arn": arn, "type": "", "account": "", "name": "",
           "service_linked": False, "note": ""}
    m = re.fullmatch(r"arn:(aws[\w-]*):iam::(\d{12}):role/((?:[^/]+/)*)([\w+=,.@-]+)", arn)
    if m:
        out.update(type="AssumedRole", account=m.group(2), name=m.group(4))
        # A service-linked role's ARN always has the /aws-service-role/ path. Going by the
        # name alone would call any role named AWSServiceRoleFor... exempt from SCPs.
        out["service_linked"] = m.group(3).startswith("aws-service-role/")
        return out
    m = re.fullmatch(r"arn:(aws[\w-]*):sts::(\d{12}):assumed-role/([\w+=,.@-]+)/(.+)", arn)
    if m:
        out.update(type="AssumedRole", account=m.group(2), name=m.group(3),
                   arn=f"arn:{m.group(1)}:iam::{m.group(2)}:role/{m.group(3)}")
        out["note"] = (f"For a role session, aws:PrincipalArn is the role's ARN, {out['arn']}. "
                       "If the role has a path, give the role ARN with its path instead.")
        if m.group(3).startswith("AWSServiceRoleFor"):
            out["note"] += (f" {m.group(3)} looks like a service-linked role, and SCPs and RCPs "
                            "don't apply to those. A session ARN doesn't show the role's path, "
                            "so give the role ARN (it has /aws-service-role/ in it) to check "
                            "that.")
        return out
    m = re.fullmatch(r"arn:(aws[\w-]*):iam::(\d{12}):user/(?:[^/]+/)*([\w+=,.@-]+)", arn)
    if m:
        out.update(type="User", account=m.group(2), name=m.group(3))
        return out
    m = re.fullmatch(r"arn:(aws[\w-]*):iam::(\d{12}):root", arn)
    if m:
        out.update(type="Account", account=m.group(2), name="root user")
        return out
    m = re.fullmatch(r"arn:(aws[\w-]*):sts::(\d{12}):federated-user/(.+)", arn)
    if m:
        out.update(type="FederatedUser", account=m.group(2), name=m.group(3))
        return out
    raise ScpError(f"{arn} doesn't look like a role, user or root ARN, like "
                   "arn:aws:iam::111122223333:role/deploy.")


ACTION_RE = re.compile(r"[A-Za-z0-9-]+:[A-Za-z0-9]+")


@dataclass
class Draft:
    """A draft SCP to try before attaching it, and where it would go."""
    policy: Policy
    target: str


def check_draft(text) -> tuple:
    """(doc, problems, warnings) for a pasted SCP. problems stop it from being used."""
    try:
        doc, _note = iampolicy.load_policy(text)
    except iampolicy.PolicyError as exc:
        return None, [str(exc)], []
    problems = policyeval.problems(doc, "scp")
    warnings = []
    keep = ("No Version set", "Old policy language version", "Duplicate Sid",
            "Over the SCP size limit")
    for f in iampolicy.analyze(doc, "scp"):
        if f.title in keep:
            warnings.append(f"{f.title}. {f.detail}".strip())
    return doc, problems, warnings


def make_draft(text, target, org=None) -> Draft:
    doc, problems, _warnings = check_draft(text)
    if problems:
        raise ScpError("The draft SCP has problems:\n" + "\n".join("- " + p for p in problems))
    if org is not None:
        target = org.find(target).id
    return Draft(Policy("draft", "draft SCP", SCP, json.dumps(doc, indent=2), draft=True,
                        doc=doc), target)


def build_request(org, account, action, resource="", region="", principal="", context=None):
    """(Request, used, principal info, resource account, notes). used maps each context
    key to (key as shown, value text, where it came from)."""
    action = str(action or "").strip()
    if not action:
        raise ScpError("Give an action to test, like s3:DeleteBucket.")
    if "*" in action or "?" in action:
        raise ScpError("Test one action at a time, like s3:DeleteBucket. Wildcards aren't "
                       "allowed here.")
    if not ACTION_RE.fullmatch(action):
        raise ScpError(f"{action} isn't an action. Write it like s3:DeleteBucket.")
    resource = str(resource or "").strip()
    if resource == "*":
        resource = ""
    if resource and not resource.startswith("arn:"):
        raise ScpError("Give the resource as an ARN, like arn:aws:s3:::my-bucket, or leave it "
                       "as * for any.")
    notes = []
    if policyeval.has_wildcard(resource):
        notes.append("The resource has * or ? in it, so it's taken as a pattern: a statement "
                     "counts only if it covers every resource the pattern could be, and one "
                     "that covers some of them makes the answer depend on the resource.")
    region = str(region or "").strip().lower()
    if region and not re.fullmatch(r"[a-z]{2}(-[a-z]+)+-\d+", region):
        raise ScpError(f"{region} doesn't look like a region, like us-east-1.")
    given = context if isinstance(context, dict) else parse_context(context)
    service = action.split(":", 1)[0].lower()
    used = {}

    def put(key, value, source):
        used[key.lower()] = (key, value, source)

    put("aws:PrincipalAccount", account.id, "the account you picked")
    if org.id:
        put("aws:PrincipalOrgID", org.id, "its organization")
        path = "/".join([org.id] + [n.id for n in org.path(account.id)[:-1]]) + "/"
        put("aws:PrincipalOrgPaths", path, "where the account sits in the organization")
    put("aws:PrincipalIsAWSService", "false", "the caller is a principal in the account")
    put("aws:SecureTransport", "true", "the AWS CLI and SDKs always use HTTPS")
    now = datetime.now(timezone.utc)
    put("aws:CurrentTime", now.strftime("%Y-%m-%dT%H:%M:%SZ"), "now")
    put("aws:EpochTime", str(int(now.timestamp())), "now")
    if region:
        put("aws:RequestedRegion", region, "you gave it")
    elif service in GLOBAL_SERVICES:
        put("aws:RequestedRegion", "us-east-1", f"{service} is a global service, its calls go "
                                                "to us-east-1")
    pinfo = None
    if principal:
        pinfo = parse_principal(principal)
        if pinfo["account"] != account.id:
            raise ScpError(f"The principal is in account {pinfo['account']}, but the test is for "
                           f"{account.name or account.id} ({account.id}). SCPs that apply to a "
                           "principal are the ones above its own account, so pick that account, "
                           "or leave the principal out.")
        put("aws:PrincipalArn", pinfo["arn"], "you gave it")
        put("aws:PrincipalType", pinfo["type"], "from the principal ARN")
        if pinfo["note"]:
            notes.append(pinfo["note"])
    res_account, res_from = "", ""
    m = re.match(r"arn:aws[\w-]*:[^:]*:[^:]*:(\d{12}):", resource)
    if m:
        res_account, res_from = m.group(1), "from the resource ARN"
    for key, value in given.items():
        if key.lower() == "aws:resourceaccount" and isinstance(value, list) and value:
            res_account, res_from = value[0], "you gave it"
    if not res_account:
        res_account, res_from = account.id, "assumed: the resource is in the same account"
    put("aws:ResourceAccount", res_account, res_from)
    if org.id and res_account in org.nodes:
        put("aws:ResourceOrgID", org.id, "the resource's account is in this organization")
        path = "/".join([org.id] + [n.id for n in org.path(res_account)[:-1]]) + "/"
        put("aws:ResourceOrgPaths", path, "where the resource's account sits")
    for key, value in given.items():
        if value is policyeval.ABSENT:
            used[key.lower()] = (key, policyeval.ABSENT, "you said it isn't set")
        else:
            used[key.lower()] = (key, list(value) if isinstance(value, (list, tuple))
                                 else [value], "you gave it")
    ctx = {k: v[1] for k, v in used.items()}
    req = policyeval.Request(action, resource, ctx)
    return req, used, pinfo, res_account, notes


# =================================================================== evaluation

@dataclass
class PolicyEval:
    policy: Policy
    assumed: bool
    results: list = None        # StatementResults, or None when the text isn't known


@dataclass
class LevelEval:
    node: Node
    ptype: str
    policies: list = field(default_factory=list)
    unread: bool = False        # which policies are attached here couldn't be read

    def allow(self, attr="result"):
        vals = []
        for pe in self.policies:
            if pe.results is None:
                vals.append(None)
                continue
            vals += [getattr(s, attr) for s in pe.results if s.effect == "Allow" and not s.error]
        got = any_of(vals)
        return None if got is False and self.unread else got

    def denies(self, attr="result") -> list:
        out = []
        for pe in self.policies:
            if pe.results is None:
                out.append((pe, None, None))
                continue
            for s in pe.results:
                if s.effect != "Deny":
                    continue
                if s.error:
                    # A Deny this can't read might block it: never skip it as if it didn't.
                    out.append((pe, s, None))
                elif getattr(s, attr) is not False:
                    out.append((pe, s, getattr(s, attr)))
        return out


@dataclass
class Part:
    ptype: str
    target: Node                # the account whose policies apply
    levels: list = field(default_factory=list)

    def decision(self, attr="result"):
        allows = [lv.allow(attr) for lv in self.levels]
        denies = [v for lv in self.levels for _pe, _s, v in lv.denies(attr)]
        return all_of(allows + [negate(any_of(denies))])


@dataclass
class Verdict:
    outcome: str                # allowed, denied or depends
    headline: str
    reason: str
    account: str
    account_name: str
    action: str
    resource: str = ""
    lines: list = field(default_factory=list)
    depends_on: list = field(default_factory=list)
    if_unset: dict = None
    blocked_by: list = field(default_factory=list)
    no_allow_at: list = field(default_factory=list)
    context: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    without_draft: dict = None
    exempt: str = ""

    def as_dict(self) -> dict:
        return asdict(self)

    @property
    def exit_code(self) -> int:
        return {"allowed": EXIT_ALLOWED, "denied": EXIT_DENIED}.get(self.outcome, EXIT_DEPENDS)


def _line(status, where, text, part="", policy="", draft=False) -> dict:
    return {"status": status, "where": where, "text": text, "part": part, "policy": policy,
            "draft": draft}


def _sentence(text, cap=True) -> str:
    """Ends text with a full stop, and starts it with a capital unless cap is False (when
    it starts with a policy name, which keeps its own spelling)."""
    text = text.strip()
    if not text:
        return text
    if cap:
        text = text[0].upper() + text[1:]
    return text if text.endswith((".", "?", "!")) else text + "."


def _pname(pe) -> str:
    p = pe.policy
    if p.draft:
        return "the draft SCP"
    return p.name + (" (assumed)" if pe.assumed else "")


def check_action(org, account, action, resource="", region="", principal="", context=None,
                 draft=None) -> Verdict:
    """Would action be blocked for a principal in account? account is a Node, an ID or a
    name. draft is a Draft to include, as if attached."""
    acct = account if isinstance(account, Node) else org.find(account, ("account",))
    if acct.kind != "account":
        raise ScpError(f"{org.where(acct.id)} isn't an account. Tests are for an account.")
    if draft is not None and draft.target not in org.nodes:
        raise ScpError("The draft SCP is attached somewhere that isn't in this organization.")
    req, used, pinfo, res_account, notes = build_request(org, acct, action, resource, region,
                                                         principal, context)
    v = _evaluate(org, acct, req, used, pinfo, res_account, notes, draft)
    if draft is not None:
        plain = _evaluate(org, acct, req, used, pinfo, res_account, list(notes), None)
        v.without_draft = {"outcome": plain.outcome, "headline": plain.headline}
        v.lines.append(_line("info", "Draft", f"Without the draft, it would be: "
                                              f"{plain.headline}."))
    v.notes += [n for n in org.notes if n not in v.notes]   # like the FullAWSAccess assumption
    return v


def _evaluate(org, acct, req, used, pinfo, res_account, notes, draft) -> Verdict:
    v = Verdict("allowed", "", "", acct.id, acct.name, req.action, req.resource,
                notes=list(notes))
    who = acct.name or acct.id
    if pinfo and pinfo["service_linked"]:
        v.exempt = "service-linked role"
        v.headline = "Allowed: service-linked role"
        v.reason = (f"{pinfo['name']} is a service-linked role. SCPs and RCPs don't apply to "
                    "service-linked roles, so nothing here can block it.")
        v.lines.append(_line("info", "Principal", v.reason))
        return v

    parts, skipped = [], []
    scp_on = org.enabled_type(SCP) and org.feature_set == "ALL"
    if acct.id == org.management:
        skipped.append(_line("info", org.where(acct.id), f"{who} is the management account. "
                             "SCPs never apply to it.", SHORT[SCP]))
    elif not scp_on:
        skipped.append(_line("info", "Organization", "SCPs aren't turned on for this "
                             "organization, so they don't limit anything.", SHORT[SCP]))
    else:
        parts.append(_part(org, SCP, acct, req, draft))

    rcp_part = None
    gaps = []           # (what it depends on, why) for things that couldn't be read
    if req.service in policyeval.RCP_SERVICES and org.enabled_type(RCP):
        if req.action.lower() == "kms:retiregrant":
            skipped.append(_line("info", "RCPs", "RCPs don't apply to kms:RetireGrant.",
                                 SHORT[RCP]))
        elif RCP in org.unreadable:
            skipped.append(_line("warn", "RCPs", "The resource control policies couldn't be "
                                 "read, so they weren't checked.", SHORT[RCP]))
            gaps.append(("the RCPs", "the resource control policies couldn't be read"))
        elif res_account not in org.nodes or org.nodes[res_account].kind != "account":
            skipped.append(_line("info", "RCPs", f"The resource's account ({res_account}) isn't "
                                 "in this organization, so its RCPs don't apply.", SHORT[RCP]))
        elif res_account == org.management:
            skipped.append(_line("info", "RCPs", "The resource is in the management account, "
                                 "and RCPs don't apply to it.", SHORT[RCP]))
        else:
            rcp_part = _part(org, RCP, org.nodes[res_account], req, None)
            parts.append(rcp_part)
    elif org.enabled_type(RCP) and res_account in org.nodes and res_account != org.management:
        names = _rcps_outside_list(org, org.nodes[res_account], req)
        if names:
            skipped.append(_line("warn", "RCPs", f"As far as AWS Kit knows, RCPs don't cover "
                                 f"{req.service}, so {join(names, 'and')} "
                                 f"{'wasn' if len(names) == 1 else 'weren'}'t checked. AWS keeps "
                                 f"adding services to RCPs: if {req.service} is one now, "
                                 f"{'it' if len(names) == 1 else 'they'} could block this.",
                                 SHORT[RCP]))
    gaps += _read_gaps(org, parts, req)
    skipped += [_line("warn", "Not read", _sentence(why)) for dep, why in gaps
                if dep != "the RCPs"]

    used_keys = set()
    for part in parts:
        for lv in part.levels:
            for pe in lv.policies:
                for s in pe.results or []:
                    used_keys |= {c.key.lower() for c in s.conditions}
    v.context = [{"key": key, "value": value if value is policyeval.ABSENT else
                  ", ".join(value) if isinstance(value, list) else str(value), "from": src}
                 for k, (key, value, src) in sorted(used.items())
                 if k in used_keys or src in ("you gave it", "you said it isn't set")]
    for item in v.context:
        if item["value"] is policyeval.ABSENT:
            item["value"] = "(not set)"
    rcp_keys = {"aws:resourceaccount", "aws:resourceorgid", "aws:resourceorgpaths"}
    if used.get("aws:resourceaccount", ("", "", ""))[2].startswith("assumed") and (
            used_keys & rcp_keys or (rcp_part is not None and _rcps_below_root(org))):
        v.notes.append("The resource's account isn't in its ARN, so it's taken to be the same "
                       "account. Give aws:ResourceAccount=ID under More context to test another.")

    outcome, headline, reason, blocked, noallow, deps = _decide(org, parts, req, "result")
    if gaps and outcome != "denied":
        # What couldn't be read could block it, so it's never Allowed.
        deps = deps + [d for d, _why in gaps]
        why = join([w for _d, w in gaps], "and")
        if outcome == "allowed":
            outcome = "depends"
            headline = "Depends on " + join([d for d, _why in gaps], "and")
            reason = (f"Nothing that could be read blocks it, but {why}. Read the org again "
                      "with permission to see it.")
        else:
            reason += f" Also, {why}."
    v.outcome, v.headline, v.reason = outcome, headline, reason
    v.blocked_by, v.no_allow_at, v.depends_on = blocked, noallow, deps
    if acct.id == org.management and outcome == "allowed":
        v.exempt = "management account"
        v.headline = "Allowed: management account"
        v.reason = (f"{who} is the management account, and SCPs never apply to it. IAM "
                    "policies still have to allow the action.")
    elif not scp_on and outcome == "allowed" and not parts:
        v.reason = "SCPs aren't turned on for this organization, so they don't limit anything."
    if outcome == "depends":
        un = _decide(org, parts, req, "if_unset")
        if un[0] != "depends" and not (gaps and un[0] == "allowed"):
            v.if_unset = {"outcome": un[0], "headline": un[1], "reason": un[2]}
    v.lines = skipped + _lines(org, parts, req)
    return v


def _read_gaps(org, parts, req) -> list:
    """(what it depends on, why) for each thing that couldn't be read from AWS and could
    block this request: policies whose attachments couldn't be listed, when they have a
    Deny that could match, and levels whose attached policies couldn't be listed."""
    out = []
    for part in parts:
        for lv in part.levels:
            if lv.node.id in org.unread_targets:
                where = org.in_words(lv.node.id)
                gap = (f"the policies attached to {where}",
                       f"which policies are attached to {where} couldn't be read")
                if gap not in out:          # the SCP and RCP paths can share a level
                    out.append(gap)
    types = {part.ptype for part in parts}
    for pid in org.unplaced:
        pol = org.policies.get(pid)
        if pol is None or pol.type not in types:
            continue
        if pol.doc is not None:
            results = policyeval.evaluate_policy(pol.doc, req)
            if not any(s.effect == "Deny" and (s.error or s.result is not False)
                       for s in results):
                continue          # only allows, or denies that don't match: can't block it
        out.append((f"where {pol.name} is attached",
                    f"{pol.name} could block it, and where it's attached couldn't be read"))
    return out


def _rcps_outside_list(org, acct, req) -> list:
    """Names of RCPs above acct with a Deny that covers req's action, for a service that
    isn't in RCP_SERVICES. AWS may have added the service since the list was written."""
    names = []
    for level in org.path(acct.id):
        for pol, _assumed in org.attached(level.id, RCP):
            if pol.id == FULL_ACCESS[RCP][0] or pol.doc is None:
                continue
            if any(s.effect == "Deny" and s.action_match and s.result is not False
                   for s in policyeval.evaluate_policy(pol.doc, req)):
                names.append(pol.name)
    return sorted(set(names))


def _rcps_below_root(org) -> bool:
    """True when some OU or account has its own RCP, so which account a resource is in
    changes which RCPs apply."""
    full = FULL_ACCESS[RCP][0]
    return any(pid != full and org.policies.get(pid) is not None and
               org.policies[pid].type == RCP
               for n in org.nodes.values() if n.kind != "root" for pid in n.policies)


def _part(org, ptype, acct, req, draft) -> Part:
    part = Part(ptype, acct)
    for level in org.path(acct.id):
        pols = org.attached(level.id, ptype)
        if draft is not None and ptype == SCP and draft.target == level.id:
            pols = pols + [(draft.policy, False)]
        lv = LevelEval(level, ptype, unread=level.id in org.unread_targets)
        for pol, assumed in pols:
            results = policyeval.evaluate_policy(pol.doc, req) if pol.doc is not None else None
            lv.policies.append(PolicyEval(pol, assumed, results))
        part.levels.append(lv)
    return part


ASK_WORDS = {"aws:requestedregion": "a region", "aws:principalarn": "a principal ARN"}


def _full_access_remark(org, lv) -> str:
    pid, name, _doc = FULL_ACCESS[lv.ptype]
    if any(pe.policy.id == pid for pe in lv.policies):
        return ""
    if org.source == "terraform":
        return f"; {name} isn't attached there in the Terraform state"
    if lv.ptype == RCP:
        return ""
    return f"; {name} was removed there"


def _decide(org, parts, req, attr) -> tuple:
    """(outcome, headline, reason, blocked_by, no_allow_at, depends_on) for attr "result"
    (what's known) or "if_unset" (if the missing keys aren't set)."""
    for part in parts:
        for lv in part.levels:
            for pe, s, val in lv.denies(attr):
                if val is True:
                    p = pe.policy
                    name = "the draft SCP" if p.draft else (
                        p.name if part.ptype == SCP else f"RCP {p.name}")
                    headline = f"Blocked by {name}"
                    desc = policyeval.describe_statement(s.statement)
                    given = policyeval.given_text(s.statement, req.context)
                    reason = (_sentence(f"{name}, {s.label}, attached to "
                                        f"{org.in_words(lv.node.id)}: it {desc}", p.draft) +
                              (" " + _sentence(f"here {given}") if given else ""))
                    blocked = [{"policy": p.display, "policy_id": p.id, "type": SHORT[part.ptype],
                                "statement": s.index + 1, "sid": s.sid,
                                "attached_to": org.where(lv.node.id),
                                "attached_to_id": lv.node.id, "draft": p.draft,
                                "text": desc}]
                    return "denied", headline, reason, blocked, [], []
    for part in parts:
        for lv in part.levels:
            if lv.allow(attr) is False:
                word = SHORT[part.ptype]
                where = org.where(lv.node.id)
                headline = f"Blocked: nothing allows it at {where}"
                if lv.policies:
                    reason = (f"{where} has no {word} that allows {req.action}"
                              f"{_full_access_remark(org, lv)}.")
                else:
                    reason = f"{where} has no {word} attached at all, so nothing is allowed there."
                cond = _conditional_allows(lv, attr, req)
                if cond:
                    reason += " " + cond
                return ("denied", headline, reason, [],
                        [{"target": where, "target_id": lv.node.id, "type": word}], [])
    deps, reasons = [], []
    for part in parts:
        for lv in part.levels:
            for pe, s, val in lv.denies(attr):
                if val is None:
                    if s is None:
                        deps.append(f"the text of {pe.policy.name}")
                        reasons.append(_sentence(f"the text of {pe.policy.name} "
                                                 f"(attached to {org.in_words(lv.node.id)}) "
                                                 "isn't known, so it wasn't checked"))
                        continue
                    if s.error:
                        deps.append(f"the text of {pe.policy.name}")
                        reasons.append(_sentence(f"{_pname(pe)}, {s.label}, attached to "
                                                 f"{org.in_words(lv.node.id)}, couldn't be "
                                                 f"checked: {s.error}", pe.policy.draft))
                        continue
                    deps += s.depends_on
                    reasons.append(_sentence(f"{_pname(pe)}, attached to "
                                             f"{org.in_words(lv.node.id)}, "
                                             f"{policyeval.describe_statement(s.statement)}",
                                             pe.policy.draft))
            if lv.allow(attr) is None:
                for pe in lv.policies:
                    if pe.results is None:
                        continue
                    for s in pe.results:
                        if s.effect == "Allow" and getattr(s, attr) is None:
                            deps += s.depends_on
                            reasons.append(_sentence(
                                f"at {org.in_words(lv.node.id)}, only {_pname(pe)} could allow "
                                f"it, and it {policyeval.describe_statement(s.statement)}"))
    if deps or reasons:
        deps = policyeval._unique(deps)
        shown = [("the resource ARN" if d == policyeval.RESOURCE else d) for d in deps]
        headline = "Depends on " + join(shown[:3], "and") + (" and more" if len(shown) > 3 else "")
        asks = [d for d in deps if d != policyeval.RESOURCE and not d.startswith("the text of")]
        tail = []
        named = [ASK_WORDS[d.lower()] for d in asks if d.lower() in ASK_WORDS]
        others = [d for d in asks if d.lower() not in ASK_WORDS]
        if named:
            tail.append(f"Give {join(named, 'and')} to test it.")
        if others:
            tail.append(f"Give a value for {join(others, 'and')} to test it.")
        if policyeval.RESOURCE in deps:
            tail.append("Give a resource ARN to test it.")
        return "depends", headline, " ".join(reasons[:2] + tail), [], [], shown
    words = " and ".join(sorted({SHORT[p.ptype] + "s" for p in parts}, reverse=True)) or "SCPs"
    if not parts:
        return ("allowed", f"Allowed by {words}", "Nothing here limits it. IAM policies "
                "still have to allow the action.", [], [], [])
    who = parts[0].target.name or parts[0].target.id
    reason = (f"Every level from the root down to {who} allows {req.action}, and nothing denies "
              "it. SCPs only limit what's allowed: IAM policies in the account still have to "
              "allow it.")
    return "allowed", f"Allowed by {words}", reason, [], [], []


def _conditional_allows(lv, attr, req) -> str:
    """'sandbox-allow allows it only when the region is eu-west-1, and here the region is
    us-east-1.' for Allow statements that cover the action but whose conditions fail."""
    out = []
    for pe in lv.policies:
        for s in pe.results or []:
            if s.effect == "Allow" and s.action_match and getattr(s, attr) is False and \
                    s.statement.get("Condition"):
                given = policyeval.given_text(s.statement, req.context)
                out.append(_sentence(f"{_pname(pe)} {policyeval.describe_statement(s.statement)}"
                                     + (f", and here {given}" if given else ""),
                                     pe.policy.draft))
    return " ".join(out[:2])


def _lines(org, parts, req) -> list:
    out = []
    for part in parts:
        word = SHORT[part.ptype]
        full = FULL_ACCESS[RCP][0]
        collapse = part.ptype == RCP and all(
            lv.allow("result") is True and any(pe.policy.id == full for pe in lv.policies)
            for lv in part.levels)
        if collapse:
            # RCPFullAWSAccess is on every level and can't be detached, so one line says it.
            out.append(_line("allow", f"Root to {org.where(part.target.id)}",
                             f"Allowed at every level by {FULL_ACCESS[RCP][1]}.", word))
        for lv in part.levels:
            where = org.where(lv.node.id)
            allow = lv.allow("result")
            allowing = [pe for pe in lv.policies if pe.results and any(
                s.effect == "Allow" and s.result is True for s in pe.results)]
            draft = any(pe.policy.draft for pe in allowing)
            if collapse:
                pass
            elif lv.unread and allow is not True:
                out.append(_line("depends", where, f"Which {word}s are attached here couldn't "
                                 "be read, so it isn't known what's allowed.", word))
            elif not lv.policies:
                out.append(_line("noallow", where, f"No {word} is attached here, so nothing is "
                                 "allowed.", word))
            elif allow is True:
                out.append(_line("allow", where, "Allowed by " +
                                 join([_pname(pe) for pe in allowing], "and") + ".", word,
                                 draft=draft))
            elif allow is False:
                attached = join([_pname(pe) for pe in lv.policies], "and")
                text = (f"Nothing here allows {req.action}{_full_access_remark(org, lv)}. "
                        f"Attached: {attached}.")
                cond = _conditional_allows(lv, "result", req)
                out.append(_line("noallow", where, text + (" " + cond if cond else ""), word))
            else:
                for pe in lv.policies:
                    if pe.results is None:
                        out.append(_line("depends", where, f"{pe.policy.name}: "
                                         f"{pe.policy.error or 'its text is not known'}",
                                         word, pe.policy.name))
                        continue
                    for s in pe.results:
                        if s.effect == "Allow" and s.result is None:
                            out.append(_line("depends", where, _sentence(
                                f"{_pname(pe)}, {s.label}, only allows it if this applies: it "
                                f"{policyeval.describe_statement(s.statement)}",
                                pe.policy.draft), word,
                                pe.policy.name, pe.policy.draft))
            for pe, s, val in lv.denies("result"):
                if s is None:
                    if allow is not None:
                        out.append(_line("depends", where, f"{pe.policy.name}: "
                                         f"{pe.policy.error or 'its text is not known'}",
                                         word, pe.policy.name))
                    continue
                if s.error:
                    out.append(_line("depends", where, _sentence(
                        f"{_pname(pe)}, {s.label}, might block it, but it couldn't be "
                        f"checked: {s.error}", pe.policy.draft), word, pe.policy.name,
                        pe.policy.draft))
                    continue
                desc = policyeval.describe_statement(s.statement)
                if val is True:
                    given = policyeval.given_text(s.statement, req.context)
                    text = _sentence(f"{_pname(pe)}, {s.label}, blocks it: it {desc}",
                                     pe.policy.draft) + \
                        (" " + _sentence(f"here {given}") if given else "")
                    out.append(_line("deny", where, text, word, pe.policy.name, pe.policy.draft))
                else:
                    missing = [("the resource ARN" if d == policyeval.RESOURCE else d)
                               for d in s.depends_on]
                    text = _sentence(f"{_pname(pe)}, {s.label}, might block it: it {desc}",
                                     pe.policy.draft)
                    if missing:
                        text += f" No value was given for {join(missing, 'or')}."
                    out.append(_line("depends", where, text, word, pe.policy.name,
                                     pe.policy.draft))
    return out


# =================================================================== summaries

def policy_rows(org, node_id, draft=None) -> list:
    """Every SCP and RCP that applies at node_id: attached right there or inherited."""
    rows = []
    path = org.path(node_id)
    rcp_full = FULL_ACCESS[RCP][0]
    for ptype in POLICY_TYPES:
        for level in path:
            pols = org.attached(level.id, ptype)
            if draft is not None and ptype == SCP and draft.target == level.id:
                pols = pols + [(draft.policy, False)]
            for pol, assumed in pols:
                if pol.id == rcp_full:
                    # Attached everywhere and can't be detached, so it's listed once.
                    if level.kind == "root":
                        rows.append({"name": pol.name, "type": "RCP",
                                     "where": "Root and every OU and account", "inherited": True,
                                     "summary": policy_summary(pol), "policy_id": pol.id,
                                     "where_id": level.id, "assumed": assumed, "draft": False,
                                     "note": "assumed" if assumed else "AWS managed"})
                    continue
                here = level.id == node_id
                rows.append({
                    "name": pol.display if pol.draft else pol.name,
                    "type": pol.short_type,
                    "where": org.where(level.id) + (" (here)" if here else ""),
                    "inherited": not here,
                    "summary": policy_summary(pol),
                    "policy_id": pol.id, "where_id": level.id,
                    "assumed": assumed, "draft": pol.draft,
                    "note": ("assumed" if assumed else "draft" if pol.draft else
                             "AWS managed" if pol.aws_managed else ""),
                })
    return rows


def policy_summary(pol, limit=160) -> str:
    if pol.doc is None:
        return pol.error or "Its text isn't known."
    text = "; ".join(policyeval.describe_policy(pol.doc))
    return (text[:limit - 1] + "…") if len(text) > limit else text


def summarize(org, node_id, draft=None) -> dict:
    """What's blocked for everything at node_id: each inherited Deny statement in plain
    words, and the levels that limit by Allow lists."""
    node = org.node(node_id)
    out = {"node": node.id, "name": node.name, "kind": node.kind, "exempt": "",
           "denies": [], "limits": [], "notes": []}
    if node.kind == "account" and node.id == org.management:
        out["exempt"] = ("This is the management account. SCPs never apply to it, and RCPs "
                         "don't apply to its resources.")
        return out
    path = org.path(node_id)
    for ptype in POLICY_TYPES:
        if not org.enabled_type(ptype) or (ptype == SCP and org.feature_set != "ALL"):
            if ptype == SCP:
                out["notes"].append("SCPs aren't turned on, so they don't limit anything.")
            continue
        if ptype in org.unreadable:
            out["notes"].append(f"The {LONG[ptype]}s couldn't be read, so they aren't shown.")
            continue
        lost = sorted(org.policies[p].name for p in org.unplaced
                      if p in org.policies and org.policies[p].type == ptype)
        if lost:
            out["notes"].append(f"Where {join(lost, 'and')} {'is' if len(lost) == 1 else 'are'}"
                                " attached couldn't be read, so they aren't shown.")
        for level in path:
            pols = org.attached(level.id, ptype)
            if draft is not None and ptype == SCP and draft.target == level.id:
                pols = pols + [(draft.policy, False)]
            if level.id in org.unread_targets:
                out["notes"].append(f"Which {SHORT[ptype]}s are attached to "
                                    f"{org.in_words(level.id)} couldn't be read.")
                continue
            allows, unlimited = [], False
            for pol, assumed in pols:
                if pol.doc is None:
                    out["notes"].append(f"{pol.name} ({org.where(level.id)}): "
                                        f"{pol.error or 'its text is not known'}")
                    continue
                for i, stmt in enumerate(iampolicy.statements(pol.doc)):
                    effect = str(stmt.get("Effect", "")).capitalize()
                    if effect == "Deny":
                        out["denies"].append({
                            "policy": pol.display, "policy_id": pol.id, "type": SHORT[ptype],
                            "where": org.where(level.id), "where_id": level.id,
                            "statement": i + 1, "sid": str(stmt.get("Sid", "") or ""),
                            "text": _sentence(policyeval.describe_statement(stmt)),
                            "draft": pol.draft})
                    elif effect == "Allow":
                        if policyeval.unconditional_allow_all(stmt):
                            unlimited = True
                        else:
                            allows.append(policyeval.describe_statement(
                                stmt, limit=12)[len("allows "):])
            if unlimited:
                continue
            where = org.where(level.id)
            word = SHORT[ptype]
            if not pols:
                text = f"No {word} is attached, so nothing is allowed there."
            elif allows:
                remark = _full_access_remark_text(org, level, ptype)
                text = f"Only allows {join(allows, 'and')}{remark}."
            else:
                text = f"Nothing is allowed there{_full_access_remark_text(org, level, ptype)}."
            out["limits"].append({"where": where, "where_id": level.id, "type": word,
                                  "text": text})
    return out


def _full_access_remark_text(org, level, ptype) -> str:
    pid, name, _doc = FULL_ACCESS[ptype]
    if any(p.id == pid for p, _ in org.attached(level.id, ptype)):
        return ""
    if org.source == "terraform":
        return f" ({name} isn't attached there in the Terraform state)"
    return f" ({name} isn't attached there)"


def blocked_text(summary) -> str:
    """The summary as plain text, for the terminal and Copy. Allow lists come first, since
    they're the less obvious limit."""
    lines = []
    if summary["exempt"]:
        return summary["exempt"] + "\n"
    if summary["limits"]:
        lines.append("Allow lists:")
        for lim in summary["limits"]:
            lines.append(f"- {lim['where']} ({lim['type']}s): {lim['text']}")
        lines.append("")
        lines.append("Denies:")
    for d in summary["denies"]:
        tag = " [draft]" if d["draft"] else ""
        kind = "" if d["type"] == "SCP" else "RCP "
        lines.append(f"- {kind}{d['policy']}{tag} ({d['where']}): {d['text']}")
    if not summary["denies"]:
        lines.append("- Nothing is denied outright.")
    if not summary["limits"]:
        lines.append("")
        lines.append("No allow lists: every level allows everything, so only the denies above "
                     "limit it.")
    for n in summary["notes"]:
        lines.append(f"Note: {n}")
    return "\n".join(lines) + "\n"


# =================================================================== text output

def tree_lines(org) -> list:
    """(prefix, node) pairs for drawing the tree with plain ASCII."""
    out = []
    if org.root not in org.nodes:
        return out
    children = org.children_map()
    stack = [(org.nodes[org.root], "", True, 0)]
    seen = set()
    while stack:            # a loop, not recursion, so a deep tree can't overflow the stack
        node, prefix, last, depth = stack.pop()
        if node.id in seen:
            continue
        seen.add(node.id)
        out.append(("" if depth == 0 else prefix + ("`-- " if last else "|-- "), node))
        kids = children.get(node.id, [])
        nxt = prefix + ("" if depth == 0 else ("    " if last else "|   "))
        for i in range(len(kids) - 1, -1, -1):
            stack.append((kids[i], nxt, i == len(kids) - 1, depth + 1))
    return out


def node_policy_names(org, node) -> str:
    names = []
    for pol, assumed in org.attached(node.id):
        if pol.id == FULL_ACCESS[RCP][0]:
            continue    # on every node and can't be detached
        tag = "*" if assumed else ""
        names.append(("RCP " if pol.type == RCP else "") + pol.name + tag)
    return ", ".join(names) or "-"


def tree_text(org) -> str:
    head = [f"Organization {org.id or '(ID unknown)'}"
            + (f", management account {org.management}" if org.management else ""),
            f"From {org.label or org.source} ({source_words(org)}). {org.summary_line()}."]
    rows = []
    for prefix, node in tree_lines(org):
        name = node.name or node.id
        kind = {"root": "", "ou": " (OU)", "account": ""}[node.kind]
        if node.id == org.management:
            kind = " (management)"
        rows.append({"tree": f"{prefix}{name}{kind}", "id": node.id,
                     "policies": node_policy_names(org, node)})
    body = table_text(rows, [("tree", "Tree"), ("id", "ID"), ("policies", "Policies")],
                      max_width=90)
    tail = []
    if any(n.assumed for n in org.nodes.values()):
        tail.append("* assumed attached, see the note below")
    if org.enabled_type(RCP):
        tail.append("RCPFullAWSAccess is on the root and every OU and account (it can't be "
                    "detached), so it isn't listed.")
    tail += [f"Note: {n}" for n in org.notes]
    return "\n".join(head + ["", body, ""] + tail) + "\n"


def source_words(org) -> str:
    base = {"aws": "read from AWS", "terraform": "Terraform"}.get(org.source, org.source or "?")
    if org.saved_at:
        base += f", snapshot saved {org.saved_at}"
    return base


def _when(stamp) -> str:
    """'2026-10-05T14:21:00Z' as local time without seconds."""
    from .common import local_time
    try:
        dt = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except ValueError:
        return str(stamp)
    return local_time(dt)[:16]


def source_short(org) -> str:
    """One short line on where the org came from, for the window."""
    if org.saved_at:
        what = "AWS" if org.source == "aws" else org.label or "Terraform"
        return f"Snapshot of {what}, saved {_when(org.saved_at)}"
    if org.source == "aws":
        return f"Read from AWS with {org.label} at {_when(org.read_at)[11:]}"
    return f"Terraform: {org.label}" if org.label else "Terraform"


def show_text(org, node, draft=None) -> str:
    path = " / ".join(n.name or n.id for n in org.path(node.id))
    kind = {"root": "Root", "ou": "OU", "account": "Account"}[node.kind]
    lines = [color(f"{kind} {node.name or node.id}  {node.id}", "bold"), f"Path: {path}"]
    if node.id == org.management:
        lines.append("This is the management account.")
    lines.append("")
    rows = policy_rows(org, node.id, draft)
    if rows:
        for r in rows:
            r["shown"] = r["name"] + (f" ({r['note']})" if r["note"] else "")
        lines.append(color("Policies that apply here", "bold"))
        lines.append(table_text(rows, [("shown", "Policy"), ("type", "Type"),
                                       ("where", "Attached at"), ("summary", "What it does")],
                                max_width=70))
    else:
        lines.append("No SCPs or RCPs apply here.")
    lines.append("")
    lines.append(color("What's blocked here", "bold"))
    lines.append(blocked_text(summarize(org, node.id, draft)).rstrip())
    if org.notes:
        lines.append("")
        lines += [f"Note: {n}" for n in org.notes]
    return "\n".join(lines) + "\n"


STATUS_WORDS = {"allow": "ALLOW", "deny": "DENY", "noallow": "NO ALLOW", "depends": "DEPENDS",
                "info": "INFO", "warn": "NOTE"}
STATUS_COLORS = {"allow": "green", "deny": "red", "noallow": "red", "depends": "yellow",
                 "info": "dim", "warn": "yellow"}
OUTCOME_COLORS = {"allowed": "green", "denied": "red", "depends": "yellow"}


def unset_keys(v: Verdict) -> list:
    """The context keys an "if not set" answer is about, without "the resource ARN", "the
    text of ..." or "where ... is attached"."""
    return [d for d in v.depends_on if not d.startswith(("the ", "where "))]


def verdict_text(v: Verdict, use_color=None) -> str:
    def c(text, name):
        return color(text, name, use_color)
    lines = [c(v.headline, OUTCOME_COLORS.get(v.outcome, "bold")), v.reason]
    if v.if_unset:
        keys = unset_keys(v)
        lines.append(f"If {join(keys, 'and')} {'is' if len(keys) == 1 else 'are'} not set: "
                     f"{v.if_unset['headline']}.")
    lines.append("")
    part = None
    width = max([len(ln["where"]) for ln in v.lines] + [8])
    for ln in v.lines:
        if ln["part"] != part and ln["part"] in ("SCP", "RCP"):
            part = ln["part"]
            lines.append(c("Service control policies" if part == "SCP" else
                           "Resource control policies, for the resource's account", "bold"))
        tag = STATUS_WORDS.get(ln["status"], ln["status"].upper())
        draft = " [draft]" if ln["draft"] else ""
        lines.append(f"  {c(tag.ljust(8), STATUS_COLORS.get(ln['status'], 'dim'))}  "
                     f"{ln['where'].ljust(width)}  {ln['text']}{draft}")
    if v.context:
        lines.append("")
        lines.append("Context: " + "; ".join(f"{x['key']}={x['value']} ({x['from']})"
                                             for x in v.context))
    for n in v.notes:
        lines.append(f"Note: {n}")
    return "\n".join(lines) + "\n"


# =================================================================== command line

SOURCE_HELP = ("A Terraform state file, terraform show -json output, a Terraform folder (runs "
               "terraform show there), or a snapshot from awskit scp save. Leave it out to read "
               "the org from AWS with the profile.")

DESCRIPTION = """\
Shows your AWS Organization as a tree with the SCPs and RCPs attached where, and tests
whether an action would be blocked in an account, by what, and why. It works offline from
Terraform state or a snapshot, or reads the org live from the management account or a
delegated administrator (read-only).
"""

EPILOG = """\
examples:
  awskit scp tree                              read the org with the current profile
  awskit scp tree terraform.tfstate.json       from Terraform state
  awskit scp show Workloads org.json           one OU: its policies and what's blocked
  awskit scp test lab ec2:RunInstances --region eu-west-1 org.json
  awskit scp test lab s3:DeleteBucket --principal arn:aws:iam::222222222222:role/deploy
  awskit scp test lab ec2:RunInstances --context ec2:InstanceType=m5.large \\
      --draft draft-scp.json --attach Workloads org.json
  awskit scp save org.json                     save a snapshot to test offline later

exit codes for test: 0 allowed by SCPs, 3 blocked, 4 depends on context that wasn't
given, 1 for errors.
"""


def _intermixed_parser():
    import argparse

    class Intermixed(argparse.ArgumentParser):
        """Lets SOURCE come after options, like awskit scp test lab s3:GetObject --region
        us-east-1 org.json. Plain argparse stops taking positionals after the first option."""
        _inner = False

        def parse_known_args(self, args=None, namespace=None):
            if self._inner:
                return super().parse_known_args(args, namespace)
            self._inner = True
            try:
                return self.parse_known_intermixed_args(args, namespace)
            finally:
                self._inner = False
    return Intermixed


def register_cli(sub, add_profiles):
    import argparse
    p = sub.add_parser("scp", help="Show your org's SCPs and test what they block",
                       description=DESCRIPTION, epilog=EPILOG,
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    ssub = p.add_subparsers(dest="scp_cmd", metavar="COMMAND",
                            parser_class=_intermixed_parser())

    def common(sp):
        add_profiles(sp, many=False)
        sp.add_argument("--full-access", choices=("auto", "everywhere", "state"), default="auto",
                        help="For Terraform input: where FullAWSAccess counts as attached. "
                             "auto (default) assumes everywhere unless the state manages it.")
        sp.add_argument("-q", "--quiet", action="store_true", help="No progress line")

    t = ssub.add_parser("tree", help="The org tree and the policies attached where")
    t.add_argument("source", nargs="?", metavar="SOURCE", help=SOURCE_HELP)
    common(t)
    t.add_argument("--json", action="store_true", help="Print JSON (the snapshot format)")

    s = ssub.add_parser("show", help="One account, OU or the root: its policies and what's "
                                     "blocked there")
    s.add_argument("target", metavar="TARGET", help="Account, OU or root, by name or ID")
    s.add_argument("source", nargs="?", metavar="SOURCE", help=SOURCE_HELP)
    common(s)
    s.add_argument("--json", action="store_true", help="Print JSON")

    te = ssub.add_parser("test", help="Would an action be blocked in an account, and by what",
                         epilog="Exit codes: 0 allowed by SCPs, 3 blocked, 4 depends on "
                                "context that wasn't given, 1 for errors.")
    te.add_argument("account", metavar="ACCOUNT", help="Account name or ID")
    te.add_argument("action", metavar="ACTION", help="One action, like s3:DeleteBucket")
    te.add_argument("source", nargs="?", metavar="SOURCE", help=SOURCE_HELP)
    te.add_argument("--resource", metavar="ARN", default="", help="Resource ARN (default *)")
    te.add_argument("-r", "--region", default="", help="aws:RequestedRegion, like us-east-1")
    te.add_argument("--principal", metavar="ARN", default="",
                    help="The caller's role or user ARN (aws:PrincipalArn)")
    te.add_argument("--context", action="append", metavar="KEY=VALUE", default=[],
                    help="Another condition key (repeatable), like aws:PrincipalTag/team=data. "
                         "!KEY means it isn't set.")
    te.add_argument("--draft", metavar="FILE", help="A draft SCP to try, as if attached")
    te.add_argument("--attach", metavar="TARGET",
                    help="Where the draft goes: root, an OU or an account (default: the account)")
    common(te)
    te.add_argument("--json", action="store_true", help="Print JSON")

    sv = ssub.add_parser("save", help="Save the org as a snapshot, to work offline later")
    sv.add_argument("file", metavar="FILE", help="Where to write it, like org.json")
    sv.add_argument("source", nargs="?", metavar="SOURCE", help=SOURCE_HELP)
    common(sv)
    p.set_defaults(func=cmd_scp)


def load_source(source, profile=None, full_access="auto", progress=None) -> Org:
    """What the command line's SOURCE points at, or the live org when it's empty."""
    if not source:
        return read_live(profile, progress=progress)
    path = Path(source).expanduser()
    if path.is_dir():
        print(color(f"Running terraform show in {path} (it starts the folder's providers)...",
                    "dim", sys.stderr.isatty()), file=sys.stderr)
        return load_folder(path, profile, full_access)
    if not path.exists():
        raise ScpError(f"{source} doesn't exist. Give a state file, show -json output, a "
                       "Terraform folder or a snapshot.")
    return load_file(path, full_access)


def cmd_scp(args) -> int:
    from .cli import err, progress_printer, resolve_profiles, run_gui
    if not getattr(args, "scp_cmd", None):
        return run_gui("scp")
    profile = resolve_profiles(args)[0]
    show = progress_printer(sys.stderr.isatty() and not args.quiet and
                            not getattr(args, "json", False))
    try:
        org = load_source(args.source, profile, args.full_access, show)
        if args.scp_cmd == "tree":
            if args.json:
                print(dumps(org), end="")
            else:
                print(tree_text(org), end="")
            return 0
        if args.scp_cmd == "save":
            path = save_snapshot(org, args.file)
            print(f"Saved {org.summary_line()} to {path}")
            return 0
        if args.scp_cmd == "show":
            node = org.find(args.target)
            if args.json:
                print(json.dumps({"node": asdict(node), "policies": policy_rows(org, node.id),
                                  "blocked": summarize(org, node.id), "notes": org.notes},
                                 indent=2))
            else:
                print(show_text(org, node), end="")
            return 0
        draft = None
        account = org.find(args.account, ("account",))
        if args.draft:
            try:
                text = Path(args.draft).expanduser().read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                raise ScpError(f"Couldn't read the draft: {exc}") from exc
            draft = make_draft(text, args.attach or account.id, org)
        elif args.attach:
            raise ScpError("--attach goes with --draft FILE.")
        v = check_action(org, account, args.action, args.resource, args.region, args.principal,
                 args.context, draft)
    except ScpError as exc:
        err(str(exc))
        return EXIT_ERROR
    except AuthError as exc:
        err(str(exc))
        return EXIT_ERROR
    if args.json:
        print(json.dumps(v.as_dict(), indent=2, default=str))
    else:
        print(verdict_text(v), end="")
    return v.exit_code
