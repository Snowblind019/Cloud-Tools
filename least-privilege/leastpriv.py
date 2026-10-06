"""Least Privilege: drafts the smallest IAM policy that covers what a role or user did.

It reads what the role or IAM user actually called, from CloudTrail Event history
(LookupEvents) or from CloudTrail files, works out the IAM action and resource each call
needed, and groups them into a policy. Then it runs the draft through Policy Check and
compares it with what the role has now, using IAM last accessed data.

Read-only. GenerateServiceLastAccessedDetails only asks IAM to build a report so it can be
read. Nothing in AWS is changed.
"""
from __future__ import annotations

import gzip
import json
import os
import re
import stat
import sys
import threading
import time
import zlib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote, urlparse

from . import iampolicy, trail
from .common import (SEVERITY_ORDER, AuthError, AwsContext, error_code, error_text,
                     is_access_denied, local_time, paginate)

DEFAULT_DAYS = 30
DEFAULT_CAP = 20000
WINDOWS = [("Last day", 1), ("Last 7 days", 7), ("Last 30 days", 30), ("Last 90 days", 90)]
COLLAPSE_AT = 10          # more resources than this for one action become a wildcard
MAX_SESSIONS = 100        # quick mode reads at most this many role session names
PAGE_SIZE = 50            # the most LookupEvents returns per call
LOOKUP_INTERVAL = 0.5     # LookupEvents allows 2 calls a second per account and region
LOOKUP_THREADS = 4
LAST_ACCESSED_WAIT = 60   # seconds to wait for IAM's last accessed report
POLL_START = 1.0
TRACKING_DAYS = 400       # how far back IAM last accessed data goes

# Files are untrusted: limits on size (after unpacking gzip) and count.
MAX_FILE_BYTES = 100 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_FILES = 20000

POLICY_SIZE_LIMIT = 6144  # managed policy size, without whitespace


class LeastPrivError(Exception):
    """Something the user can fix. The message says what, in a plain sentence."""


# =================================================================== who

@dataclass
class Principal:
    kind: str           # "role", "user", or "" for a bare name read offline (either one)
    name: str
    arn: str = ""
    account: str = ""
    partition: str = "aws"

    @property
    def label(self) -> str:
        return f"{self.kind or 'role or user'} {self.name}"

    def as_dict(self) -> dict:
        return {"kind": self.kind, "name": self.name, "arn": self.arn, "account": self.account}


NAME_RE = re.compile(r"[\w+=,.@-]{1,128}")
PRINCIPAL_ARN = re.compile(r"arn:(aws[\w-]*):(iam|sts)::(\d{12}):(role|user|assumed-role)/(.+)$")


def parse_principal(text: str) -> Principal:
    """A role or user name, role/NAME, user/NAME, or an ARN. Needs no AWS call."""
    text = (text or "").strip()
    if not text:
        raise LeastPrivError("Type a role or user name, or its ARN.")
    if text == "root" or text.endswith(":root"):
        raise LeastPrivError("The root user can't be limited by an IAM policy. Pick a role "
                             "or an IAM user.")
    m = PRINCIPAL_ARN.match(text)
    if m:
        partition, _svc, account, kind, rest = m.groups()
        if kind == "assumed-role":
            # A session ARN. The role's own ARN has a path we can't see from here.
            return Principal("role", rest.split("/")[0], "", account, partition)
        name = rest.rsplit("/", 1)[-1]
        if not NAME_RE.fullmatch(name):
            raise LeastPrivError(f"{name} isn't a valid {kind} name.")
        return Principal(kind, name, text, account, partition)
    if text.startswith("arn:"):
        raise LeastPrivError("That ARN isn't a role or an IAM user. Use something like "
                             "arn:aws:iam::111111111111:role/NAME.")
    kind = ""
    m = re.match(r"(role|user)/(.+)$", text)
    if m:
        kind, text = m.group(1), m.group(2).rsplit("/", 1)[-1]
    if not NAME_RE.fullmatch(text):
        raise LeastPrivError(f"{text} isn't a valid role or user name.")
    return Principal(kind, text)


def _partition_of(arn: str) -> str:
    parts = (arn or "").split(":")
    return parts[1] if len(parts) > 2 and parts[0] == "arn" and parts[1] else "aws"


def resolve_principal(ctx, p: Principal, notes=None) -> Principal:
    """Look the role or user up in the profile's account, to get its full ARN."""
    account = ctx.account
    partition = _partition_of(ctx.identity().get("Arn", ""))
    if p.account and p.account != account:
        raise LeastPrivError(f"That {p.kind or 'role'} is in account {p.account}, but this "
                             f"profile is signed in to account {account}. Use a profile for "
                             f"{p.account}.")
    iam = ctx.client("iam")
    denied = None
    if p.kind in ("role", ""):
        try:
            role = iam.get_role(RoleName=p.name)["Role"]
            return Principal("role", role["RoleName"], role["Arn"], account,
                             _partition_of(role["Arn"]))
        except Exception as exc:  # noqa: BLE001
            if is_access_denied(exc):
                denied = exc
            elif error_code(exc) != "NoSuchEntity":
                raise
            elif p.kind == "role":
                raise LeastPrivError(f"There's no role named {p.name} in account "
                                     f"{account}.") from None
    if p.kind in ("user", "") and denied is None:
        try:
            user = iam.get_user(UserName=p.name)["User"]
            return Principal("user", user["UserName"], user["Arn"], account,
                             _partition_of(user["Arn"]))
        except Exception as exc:  # noqa: BLE001
            if is_access_denied(exc):
                denied = exc
            elif error_code(exc) != "NoSuchEntity":
                raise
            elif p.kind == "user":
                raise LeastPrivError(f"There's no IAM user named {p.name} in account "
                                     f"{account}.") from None
    if denied is not None:
        kind = p.kind or "role"
        arn = p.arn or f"arn:{partition}:iam::{account}:{kind}/{p.name}"
        if notes is not None:
            notes.append(f"Couldn't look up the {kind} ({error_text(denied, ctx.profile)}), so "
                         f"it's taken to be {arn}.")
        return Principal(kind, p.name, arn, account, partition)
    raise LeastPrivError(f"There's no role or IAM user named {p.name} in account {account}.")


def identity_of(detail: dict) -> tuple:
    """(kind, name, account, arn) of whoever made a call, for roles and IAM users.
    kind is "" for anyone else (AWS services, root, federated users)."""
    ident = detail.get("userIdentity") if isinstance(detail, dict) else None
    if not isinstance(ident, dict):
        return "", "", "", ""
    itype = ident.get("type")
    if itype == "AssumedRole":
        ctxt = ident.get("sessionContext") if isinstance(ident.get("sessionContext"), dict) else {}
        issuer = ctxt.get("sessionIssuer") if isinstance(ctxt.get("sessionIssuer"), dict) else {}
        name = str(issuer.get("userName") or "")
        account = str(issuer.get("accountId") or ident.get("accountId") or "")
        arn = str(issuer.get("arn") or "")
        if not name:
            m = re.match(r"arn:[\w-]+:sts::(\d{12}):assumed-role/([^/]+)/",
                         str(ident.get("arn") or ""))
            if m:
                account, name = account or m.group(1), m.group(2)
        return ("role", name, account, arn) if name else ("", "", "", "")
    if itype == "IAMUser":
        arn = str(ident.get("arn") or "")
        name = str(ident.get("userName") or arn.rsplit("/", 1)[-1])
        return ("user", name, str(ident.get("accountId") or ""), arn) if name else ("", "", "", "")
    return "", "", "", ""


def is_principal(p: Principal, detail: dict) -> bool:
    """The authoritative check: was this call made by the role (any of its sessions) or user?
    Role names are unique in an account whatever their path, so name and account decide."""
    kind, name, account, arn = identity_of(detail)
    if not kind or (p.kind and kind != p.kind):
        return False
    if p.arn and arn and arn == p.arn:
        return True
    return name.lower() == p.name.lower() and (not p.account or not account or
                                               account == p.account)


ASSUME_EVENTS = ("AssumeRole", "AssumeRoleWithWebIdentity", "AssumeRoleWithSAML")


def _role_arn_matches(p: Principal, arn: str) -> bool:
    m = re.match(r"arn:[\w-]+:iam::(\d{12}):role/(?:.*/)?([^/]+)$", arn or "")
    if not m or p.kind == "user":
        return False
    return m.group(2).lower() == p.name.lower() and (not p.account or m.group(1) == p.account)


def assumed_session(p: Principal, detail: dict):
    """For an event where someone assumed this role: the session name it got ("" when the
    call failed or the name isn't there). None for any other event."""
    if detail.get("eventSource") != "sts.amazonaws.com" or \
            detail.get("eventName") not in ASSUME_EVENTS:
        return None
    rp = _params(detail)
    if not _role_arn_matches(p, str(rp.get("roleArn") or "")):
        return None
    if detail.get("errorCode"):
        return ""
    resp = detail.get("responseElements")
    resp = resp if isinstance(resp, dict) else {}
    user = resp.get("assumedRoleUser") if isinstance(resp.get("assumedRoleUser"), dict) else {}
    m = re.match(r"arn:[\w-]+:sts::\d{12}:assumed-role/[^/]+/(.+)$", str(user.get("arn") or ""))
    if m:
        return m.group(1)
    return str(rp.get("roleSessionName") or "")


# =================================================================== events to IAM actions

# eventSource (the part before .amazonaws.com) to IAM service prefix, where they differ.
SERVICE_PREFIX = {
    "monitoring": "cloudwatch",
    "email": "ses",
    "tagging": "tag",
}

# Services whose eventSource is the same as their IAM prefix.
KNOWN_SERVICES = frozenset("""
access-analyzer account acm acm-pca airflow amplify appconfig application-autoscaling
apprunner appsync athena autoscaling backup batch bedrock budgets ce cloud9 cloudformation
cloudfront cloudhsm cloudshell cloudtrail codeartifact codebuild codecommit
codeconnections codedeploy codepipeline codestar-connections cognito-identity cognito-idp
comprehend compute-optimizer config databrew datasync detective dms dynamodb ec2
ec2-instance-connect ec2messages ecr ecr-public ecs eks elasticache elasticbeanstalk
elasticfilesystem elasticloadbalancing elasticmapreduce emr-serverless es events firehose
fms fsx globalaccelerator glue guardduty health iam identitystore imagebuilder inspector2
iot kafka kinesis kinesisanalytics kinesisvideo kms lakeformation lambda license-manager
lightsail logs macie2 memorydb mq network-firewall notifications organizations pipes
polly quicksight ram rds rds-data redshift redshift-data rekognition resource-explorer-2
resource-groups route53 route53domains route53resolver s3 sagemaker scheduler
secretsmanager securityhub servicecatalog servicequotas ses shield sns sqs sso
sso-directory ssm ssm-contacts ssm-incidents ssmmessages states storagegateway sts
support textract transcribe transfer translate trustedadvisor vpc-lattice waf
waf-regional wafv2 xray
""".split())

# Not calls a policy controls, by eventSource.
SKIP_SOURCES = {"signin": "console sign-ins", "sso-signin": "console sign-ins"}

SKIP_EVENT_TYPES = {
    "AwsServiceEvent": "AWS service events",
    "AwsConsoleSignIn": "console sign-ins",
    "AwsConsoleAction": "console actions that aren't API calls",
    "AwsCloudTrailInsight": "CloudTrail Insights events",
    "AwsVpceEvent": "VPC endpoint events",
}

UNMAPPABLE_SERVICES = {
    "apigateway": "API Gateway permissions are HTTP methods on resource paths (apigateway:GET, "
                  "POST and so on), not its API names. Write these by hand.",
}

UNMAPPABLE_EVENTS = {
    ("dynamodb", "TransactWriteItems"): "Needs PutItem, UpdateItem, DeleteItem or "
                                        "ConditionCheckItem for each item, which the event "
                                        "doesn't list.",
    ("dynamodb", "ExecuteStatement"): "PartiQL needs dynamodb:PartiQLSelect, PartiQLInsert, "
                                      "PartiQLUpdate or PartiQLDelete, depending on the "
                                      "statement.",
    ("dynamodb", "BatchExecuteStatement"): "PartiQL needs dynamodb:PartiQLSelect, "
                                           "PartiQLInsert, PartiQLUpdate or PartiQLDelete, "
                                           "depending on the statements.",
    ("dynamodb", "ExecuteTransaction"): "PartiQL needs dynamodb:PartiQLSelect, PartiQLInsert, "
                                        "PartiQLUpdate or PartiQLDelete, depending on the "
                                        "statements.",
}

# Calls that every principal can make, so a policy doesn't need them.
NO_PERMISSION = {("sts", "GetCallerIdentity")}

# eventName to IAM action(s), for the well-known names that differ. Everything else uses
# the eventName, with any API version suffix (Lambda's 20150331v2) taken off.
_S3 = {
    "ListObjects": ["ListBucket"], "ListObjectsV2": ["ListBucket"], "HeadBucket": ["ListBucket"],
    "ListObjectVersions": ["ListBucketVersions"], "HeadObject": ["GetObject"],
    "ListBuckets": ["ListAllMyBuckets"],
    "ListMultipartUploads": ["ListBucketMultipartUploads"],
    "ListParts": ["ListMultipartUploadParts"],
    "CreateMultipartUpload": ["PutObject"], "InitiateMultipartUpload": ["PutObject"],
    "UploadPart": ["PutObject"], "UploadPartCopy": ["PutObject"],
    "CompleteMultipartUpload": ["PutObject"], "CopyObject": ["PutObject"],
    "DeleteObjects": ["DeleteObject"], "SelectObjectContent": ["GetObject"],
    "GetBucketEncryption": ["GetEncryptionConfiguration"],
    "PutBucketEncryption": ["PutEncryptionConfiguration"],
    "DeleteBucketEncryption": ["PutEncryptionConfiguration"],
    "GetBucketLifecycle": ["GetLifecycleConfiguration"],
    "GetBucketLifecycleConfiguration": ["GetLifecycleConfiguration"],
    "PutBucketLifecycle": ["PutLifecycleConfiguration"],
    "PutBucketLifecycleConfiguration": ["PutLifecycleConfiguration"],
    "DeleteBucketLifecycle": ["PutLifecycleConfiguration"],
    "GetBucketCors": ["GetBucketCORS"], "PutBucketCors": ["PutBucketCORS"],
    "DeleteBucketCors": ["PutBucketCORS"],
    "GetBucketReplication": ["GetReplicationConfiguration"],
    "PutBucketReplication": ["PutReplicationConfiguration"],
    "DeleteBucketReplication": ["PutReplicationConfiguration"],
    "DeleteBucketTagging": ["PutBucketTagging"],
    "DeleteBucketPublicAccessBlock": ["PutBucketPublicAccessBlock"],
    "DeleteAccountPublicAccessBlock": ["PutAccountPublicAccessBlock"],
    "DeleteBucketOwnershipControls": ["PutBucketOwnershipControls"],
    "GetBucketNotificationConfiguration": ["GetBucketNotification"],
    "PutBucketNotificationConfiguration": ["PutBucketNotification"],
    "GetBucketAccelerateConfiguration": ["GetAccelerateConfiguration"],
    "PutBucketAccelerateConfiguration": ["PutAccelerateConfiguration"],
    "GetBucketAnalyticsConfiguration": ["GetAnalyticsConfiguration"],
    "ListBucketAnalyticsConfigurations": ["GetAnalyticsConfiguration"],
    "PutBucketAnalyticsConfiguration": ["PutAnalyticsConfiguration"],
    "DeleteBucketAnalyticsConfiguration": ["PutAnalyticsConfiguration"],
    "GetBucketInventoryConfiguration": ["GetInventoryConfiguration"],
    "ListBucketInventoryConfigurations": ["GetInventoryConfiguration"],
    "PutBucketInventoryConfiguration": ["PutInventoryConfiguration"],
    "DeleteBucketInventoryConfiguration": ["PutInventoryConfiguration"],
    "GetBucketMetricsConfiguration": ["GetMetricsConfiguration"],
    "ListBucketMetricsConfigurations": ["GetMetricsConfiguration"],
    "PutBucketMetricsConfiguration": ["PutMetricsConfiguration"],
    "DeleteBucketMetricsConfiguration": ["PutMetricsConfiguration"],
    "GetBucketIntelligentTieringConfiguration": ["GetIntelligentTieringConfiguration"],
    "ListBucketIntelligentTieringConfigurations": ["GetIntelligentTieringConfiguration"],
    "PutBucketIntelligentTieringConfiguration": ["PutIntelligentTieringConfiguration"],
    "DeleteBucketIntelligentTieringConfiguration": ["PutIntelligentTieringConfiguration"],
    "GetObjectLockConfiguration": ["GetBucketObjectLockConfiguration"],
    "PutObjectLockConfiguration": ["PutBucketObjectLockConfiguration"],
}
ACTION_MAP = {("s3", k): v for k, v in _S3.items()}
ACTION_MAP.update({
    ("lambda", "Invoke"): ["InvokeFunction"],
    ("lambda", "InvokeWithResponseStream"): ["InvokeFunction"],
    ("kms", "ReEncrypt"): ["ReEncryptFrom", "ReEncryptTo"],
    ("dynamodb", "TransactGetItems"): ["GetItem"],
})

_VERSION_SUFFIX = re.compile(r"^([A-Za-z][A-Za-z0-9]*?[A-Za-z])(\d{8}(?:v\d+)?|\d{4}_\d{2}_\d{2})$")
_ACTION_NAME = re.compile(r"[A-Za-z][A-Za-z0-9]*")


def strip_version(name: str) -> str:
    """GetFunction20150331v2 -> GetFunction. No IAM action ends in a date."""
    m = _VERSION_SUFFIX.match(name or "")
    return m.group(1) if m else (name or "")


# UnauthorizedException is what a few services (AWS IoT, AppSync) say when IAM says no.
DENIED_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
                "Client.UnauthorizedOperation", "AuthorizationError",
                "AuthorizationErrorException", "UnauthorizedAccess", "UnauthorizedException"}
# The request never got as far as a permission check.
AUTH_FAILURE_CODES = {"InvalidClientTokenId", "ExpiredToken", "ExpiredTokenException",
                      "SignatureDoesNotMatch", "UnrecognizedClientException", "AuthFailure",
                      "Client.AuthFailure", "IncompleteSignature", "MissingAuthenticationToken",
                      "InvalidAccessKeyId", "RequestExpired", "Client.RequestExpired"}


def is_denied_code(code: str) -> bool:
    code = code or ""
    return code in DENIED_CODES or "AccessDenied" in code or code.endswith(".UnauthorizedOperation")


# Data events: Event history never has these. Patterns in Policy Check's format.
DATA_EVENT_ACTIONS = {
    "s3:GetObject": "S3 object reads", "s3:PutObject": "S3 object writes",
    "s3:DeleteObject": "S3 object deletes", "lambda:InvokeFunction": "Lambda invokes",
    "dynamodb:GetItem": "DynamoDB item calls", "dynamodb:PutItem": "DynamoDB item calls",
    "dynamodb:UpdateItem": "DynamoDB item calls", "dynamodb:DeleteItem": "DynamoDB item calls",
    "dynamodb:Query": "DynamoDB item calls", "dynamodb:Scan": "DynamoDB item calls",
    "dynamodb:BatchGetItem": "DynamoDB item calls",
    "dynamodb:BatchWriteItem": "DynamoDB item calls",
    "sqs:SendMessage": "SQS messages", "sqs:ReceiveMessage": "SQS messages",
    "sqs:DeleteMessage": "SQS messages", "sns:Publish": "SNS publishes",
}


@dataclass
class Where:
    partition: str
    region: str
    account: str

    def arn(self, service, resource, region=None, account=None) -> str:
        """resource is used as given, so the caller passes event names through literal().
        A region or account given here comes from the event and is made literal here."""
        r = self.region if region is None else literal(region)
        a = self.account if account is None else literal(account)
        return f"arn:{self.partition}:{service}:{r}:{a}:{resource}"


def _params(detail) -> dict:
    rp = detail.get("requestParameters") if isinstance(detail, dict) else None
    return rp if isinstance(rp, dict) else {}


def _str(value) -> str:
    return value if isinstance(value, str) else ""


def _strs(value) -> list:
    """The strings in a list parameter. A plain string isn't split into its characters."""
    return [v for v in value if isinstance(v, str) and v] if isinstance(value, list) else []


_SPECIAL = re.compile(r"[*?$]")


def literal(value: str) -> str:
    """A name or ARN taken from an event, made safe to put in a policy. In a Resource, * and ?
    are wildcards and ${...} is a policy variable, so a name like "*" would grant every
    resource. IAM reads ${*}, ${?} and ${$} as the plain characters, so they're written that
    way. AWS names almost never have these characters; only the parts the draft adds on
    purpose (like /* after a bucket) are left as wildcards."""
    return _SPECIAL.sub(lambda m: "${" + m.group() + "}", value)


def find_all(obj, key, limit=500) -> list:
    """Every string value under key, anywhere in obj (a few levels deep)."""
    out = []
    stack = [(obj, 0)]
    while stack and len(out) < limit:
        cur, depth = stack.pop()
        if depth > 6:
            continue
        if isinstance(cur, dict):
            for k, v in cur.items():
                if k == key and isinstance(v, str) and v:
                    out.append(v)
                elif k == key and isinstance(v, list):
                    out += [x for x in v if isinstance(x, str) and x]
                elif isinstance(v, (dict, list)):
                    stack.append((v, depth + 1))
        elif isinstance(cur, list):
            stack += [(v, depth + 1) for v in cur]
    return sorted(set(out))


ANY = frozenset({"*"})


# ---- per service resources

S3_ACCOUNT_ACTIONS = {"ListAllMyBuckets", "GetAccountPublicAccessBlock",
                      "PutAccountPublicAccessBlock", "ListAccessPoints", "ListJobs",
                      "CreateJob", "ListStorageLensConfigurations"}


def s3_object_action(action: str) -> bool:
    return action in ("AbortMultipartUpload", "ListMultipartUploadParts", "RestoreObject") or (
        "Object" in action and "Bucket" not in action)


def _s3(action, rp, detail, w):
    if action in S3_ACCOUNT_ACTIONS:
        return set(ANY)
    bucket = _str(rp.get("bucketName"))
    if not bucket or "/" in bucket:
        return set(ANY)
    bucket = literal(bucket)
    if s3_object_action(action):
        return {f"arn:{w.partition}:s3:::{bucket}/*"}
    return {f"arn:{w.partition}:s3:::{bucket}"}


DYNAMODB_ANY = {"ListTables", "ListBackups", "ListGlobalTables", "DescribeLimits",
                "DescribeEndpoints", "ListStreams", "ListExports", "ListImports",
                "ListContributorInsights", "DescribeReservedCapacity",
                "DescribeReservedCapacityOfferings"}


def _dynamodb(action, rp, detail, w):
    if action in DYNAMODB_ANY:
        return set(ANY)
    out = set()
    for key in ("tableArn", "resourceArn", "streamArn", "backupArn"):
        v = _str(rp.get(key))
        if v.startswith("arn:") and ":dynamodb:" in v:
            out.add(literal(v))
    tables = find_all(rp, "tableName")
    for t in tables:
        if t.startswith("arn:"):
            out.add(literal(t))
        else:
            out.add(w.arn("dynamodb", f"table/{literal(t)}"))
    index = _str(rp.get("indexName"))
    if index and len(tables) == 1 and not tables[0].startswith("arn:"):
        out.add(w.arn("dynamodb", f"table/{literal(tables[0])}/index/{literal(index)}"))
    return out or set(ANY)


def lambda_function(value: str, w: Where) -> tuple:
    """(function ARN, qualifier) from a name, partial ARN or full ARN."""
    v = value.strip()
    m = re.match(r"arn:[\w-]+:lambda:([\w-]+):(\d{12}):function:([^:]+)(?::(.+))?$", v)
    if m:
        return (w.arn("lambda", f"function:{literal(m.group(3))}", m.group(1), m.group(2)),
                m.group(4) or "")
    m = re.match(r"(\d{12}):function:([^:]+)(?::(.+))?$", v)
    if m:
        return (w.arn("lambda", f"function:{literal(m.group(2))}", account=m.group(1)),
                m.group(3) or "")
    m = re.match(r"([\w-]+)(?::([\w$-]+))?$", v)
    if m:
        return w.arn("lambda", f"function:{m.group(1)}"), m.group(2) or ""
    return "", ""


def _lambda(action, rp, detail, w):
    if "EventSourceMapping" in action or "Layer" in action or "CodeSigningConfig" in action:
        return set(ANY)
    name = _str(rp.get("functionName")) or _str(rp.get("resource"))
    if not name:
        return set(ANY)
    arn, qualifier = lambda_function(name, w)
    if not arn:
        return set(ANY)
    out = {arn}
    if qualifier or _str(rp.get("qualifier")):
        out.add(arn + ":*")
    return out


def sqs_queue_arn(url: str, w: Where) -> str:
    """https://sqs.us-east-1.amazonaws.com/111111111111/name -> the queue's ARN."""
    try:
        u = urlparse(url)
    except ValueError:
        return ""
    parts = [p for p in (u.path or "").split("/") if p]
    if len(parts) != 2 or not re.fullmatch(r"\d{12}", parts[0]):
        return ""
    host = (u.hostname or "").lower()
    region = None   # the event's own region
    m = re.match(r"sqs\.([a-z0-9-]+)\.", host) or \
        re.match(r"([a-z]{2}(?:-[a-z]+)+-\d)\.queue\.", host)
    if m:
        region = m.group(1)
    elif host.startswith("queue.amazonaws.com"):
        region = "us-east-1"
    return w.arn("sqs", literal(parts[1]), region, parts[0])


def _sqs(action, rp, detail, w):
    url = _str(rp.get("queueUrl"))
    if url:
        arn = sqs_queue_arn(url, w)
        return {arn} if arn else set(ANY)
    name = _str(rp.get("queueName"))
    if name and action in ("CreateQueue", "GetQueueUrl"):
        owner = _str(rp.get("queueOwnerAWSAccountId"))
        return {w.arn("sqs", literal(name), account=owner or None)}
    return set(ANY)


def _sns(action, rp, detail, w):
    for key in ("topicArn", "targetArn"):
        v = _str(rp.get(key))
        if v.startswith("arn:") and ":sns:" in v:
            return {literal(v)}
    name = _str(rp.get("name"))
    if action == "CreateTopic" and name:
        return {w.arn("sns", literal(name))}
    return set(ANY)


KMS_ANY = {"CreateKey", "ListKeys", "ListAliases", "GenerateRandom", "CreateCustomKeyStore",
           "DescribeCustomKeyStores", "ListRetirableGrants", "ConnectCustomKeyStore"}
UUIDISH = re.compile(r"(mrk-)?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
                     r"|mrk-[0-9a-f]{32}")


def _kms(action, rp, detail, w):
    if action in KMS_ANY:
        return set(ANY)
    out = set()
    for r in detail.get("resources") or []:
        if isinstance(r, dict) and r.get("type") == "AWS::KMS::Key" and \
                str(r.get("ARN", "")).startswith("arn:"):
            out.add(literal(str(r["ARN"])))
    if not out:
        for key in ("keyId", "sourceKeyId", "destinationKeyId", "targetKeyId"):
            v = _str(rp.get(key))
            if v.startswith("arn:") and ":key/" in v:
                out.add(literal(v))
            elif UUIDISH.fullmatch(v):
                out.add(w.arn("kms", f"key/{v}"))
    if action in ("CreateAlias", "DeleteAlias", "UpdateAlias"):
        alias = _str(rp.get("aliasName"))
        if alias.startswith("alias/"):
            out.add(w.arn("kms", literal(alias)))
        elif alias.startswith("arn:"):
            out.add(literal(alias))
    return out or set(ANY)


def secret_arn(value: str, w: Where) -> str:
    """Name-based secret ARNs end in - and 6 random characters, so a name gets -??????."""
    if value.startswith("arn:"):
        return literal(value) if ":secretsmanager:" in value and ":secret:" in value else ""
    return w.arn("secretsmanager", f"secret:{literal(value)}-??????")


def _secretsmanager(action, rp, detail, w):
    if action in ("ListSecrets", "GetRandomPassword", "BatchGetSecretValue"):
        return set(ANY)
    value = _str(rp.get("secretId")) or (_str(rp.get("name")) if action == "CreateSecret" else "")
    arn = secret_arn(value, w) if value else ""
    return {arn} if arn else set(ANY)


def parameter_arn(name: str, w: Where) -> str:
    if name.startswith("arn:"):
        return literal(name) if ":ssm:" in name and ":parameter/" in name else ""
    return w.arn("ssm", "parameter/" + literal(name.lstrip("/")))


def ssm_document_arn(name: str, w: Where) -> str:
    if name.startswith("arn:"):
        return literal(name)
    if name.startswith("AWS-") or name.startswith("Amazon"):  # owned by AWS, no account
        return w.arn("ssm", f"document/{literal(name)}", account="")
    return w.arn("ssm", f"document/{literal(name)}")


def _ssm(action, rp, detail, w):
    if "Parameter" in action and action not in ("DescribeParameters",):
        names = [_str(rp.get("name"))] if _str(rp.get("name")) else []
        names += _strs(rp.get("names"))
        out = {parameter_arn(n, w) for n in names} - {""}
        path = _str(rp.get("path"))
        if action == "GetParametersByPath" and path:
            base = parameter_arn(path.rstrip("/") or "/", w).rstrip("/")
            if not base:
                return set(ANY)
            out |= {base, base + "/*"}
        return out or set(ANY)
    if action == "SendCommand":
        doc = _str(rp.get("documentName"))
        ids = _strs(rp.get("instanceIds"))
        if not doc:
            return set(ANY)
        out = {ssm_document_arn(doc, w)}
        if ids:
            out |= {w.arn("ec2", f"instance/{literal(i)}") for i in ids if i.startswith("i-")}
            out |= {w.arn("ssm", f"managed-instance/{literal(i)}") for i in ids
                    if i.startswith("mi-")}
        else:  # sent to targets by tag, so any instance
            out.add(w.arn("ec2", "instance/*"))
        return out
    if action == "StartSession":
        target = _str(rp.get("target"))
        if not target.startswith("i-"):
            return set(ANY)
        doc = _str(rp.get("documentName")) or "SSM-SessionManagerRunShell"
        return {w.arn("ec2", f"instance/{literal(target)}"), ssm_document_arn(doc, w)}
    return set(ANY)


def _logs(action, rp, detail, w):
    if action.startswith("Describe") and action not in ("DescribeLogStreams",
                                                         "DescribeSubscriptionFilters",
                                                         "DescribeMetricFilters"):
        return set(ANY)
    names = []
    for key in ("logGroupName", "logGroupIdentifier"):
        v = _str(rp.get(key))
        if v:
            names.append(v)
    for key in ("logGroupNames", "logGroupIdentifiers"):
        names += _strs(rp.get(key))
    out = set()
    for n in names:
        m = re.match(r"arn:[\w-]+:logs:([\w-]+):(\d{12}):log-group:([^:]+)", n)
        if m:
            out.add(w.arn("logs", f"log-group:{literal(m.group(3))}:*", m.group(1),
                          m.group(2)))
        elif not n.startswith("arn:"):
            out.add(w.arn("logs", f"log-group:{literal(n)}:*"))
    return out or set(ANY)


IAM_POLICY_ACTIONS = {"CreatePolicyVersion", "DeletePolicyVersion", "GetPolicy",
                      "GetPolicyVersion", "ListPolicyVersions", "SetDefaultPolicyVersion",
                      "DeletePolicy", "TagPolicy", "UntagPolicy", "ListPolicyTags",
                      "ListEntitiesForPolicy"}


def _iam_path(rp) -> str:
    path = _str(rp.get("path")) or "/"
    if not path.startswith("/"):
        path = "/" + path
    return literal(path if path.endswith("/") else path + "/")


def _iam(action, rp, detail, w):
    acct = w.account

    def arn(res):
        return f"arn:{w.partition}:iam::{acct}:{res}"

    if action in IAM_POLICY_ACTIONS:
        v = _str(rp.get("policyArn"))
        return {literal(v)} if v.startswith("arn:") else set(ANY)
    if action == "CreatePolicy" and _str(rp.get("policyName")):
        return {arn("policy" + _iam_path(rp) + literal(rp["policyName"]))}
    profile = literal(_str(rp.get("instanceProfileName")))
    if "InstanceProfile" in action and action != "ListInstanceProfilesForRole" and profile:
        return {arn("instance-profile" + _iam_path(rp) + profile)
                if action == "CreateInstanceProfile" else arn(f"instance-profile/{profile}")}
    group = literal(_str(rp.get("groupName")))
    if group and ("Group" in action or action in ("AddUserToGroup", "RemoveUserFromGroup")) \
            and action != "ListGroupsForUser":
        return {arn(f"group/{group}")}
    role = literal(_str(rp.get("roleName")))
    if role:
        return {arn("role" + _iam_path(rp) + role) if action == "CreateRole"
                else arn(f"role/{role}")}
    user = literal(_str(rp.get("userName")))
    if user:
        return {arn("user" + _iam_path(rp) + user) if action == "CreateUser"
                else arn(f"user/{user}")}
    if group:
        return {arn(f"group/{group}")}
    for key in ("openIDConnectProviderArn", "sAMLProviderArn"):
        v = _str(rp.get(key))
        if v.startswith("arn:"):
            return {literal(v)}
    return set(ANY)


EC2_INSTANCE_ACTIONS = {"StartInstances", "StopInstances", "RebootInstances",
                        "TerminateInstances", "GetConsoleOutput", "GetConsoleScreenshot",
                        "GetPasswordData", "MonitorInstances", "UnmonitorInstances",
                        "ModifyInstanceMetadataOptions", "ModifyInstanceAttribute",
                        "ResetInstanceAttribute", "AssociateIamInstanceProfile"}
EC2_SG_ACTIONS = {"AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
                  "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress",
                  "DeleteSecurityGroup", "ModifySecurityGroupRules",
                  "UpdateSecurityGroupRuleDescriptionsIngress",
                  "UpdateSecurityGroupRuleDescriptionsEgress"}
EC2_VOLUME_ACTIONS = {"DeleteVolume", "ModifyVolume", "AttachVolume", "DetachVolume"}
# ID prefix -> (ARN resource type, ARN has the account)
EC2_ID_TYPES = {"i": ("instance", True), "vol": ("volume", True),
                "sg": ("security-group", True), "snap": ("snapshot", False),
                "ami": ("image", False), "vpc": ("vpc", True), "subnet": ("subnet", True),
                "eni": ("network-interface", True), "rtb": ("route-table", True),
                "igw": ("internet-gateway", True), "nat": ("natgateway", True),
                "acl": ("network-acl", True), "lt": ("launch-template", True),
                "eipalloc": ("elastic-ip", True), "vpce": ("vpc-endpoint", True),
                "tgw": ("transit-gateway", True), "dopt": ("dhcp-options", True)}


def ec2_id_arn(rid: str, w: Where) -> str:
    m = re.fullmatch(r"([a-z]+)-[0-9a-f]{8,17}", rid or "")
    if not m or m.group(1) not in EC2_ID_TYPES:
        return ""
    typ, with_account = EC2_ID_TYPES[m.group(1)]
    return w.arn("ec2", f"{typ}/{rid}", account=None if with_account else "")


def _ec2(action, rp, detail, w):
    out = set()
    if action in EC2_INSTANCE_ACTIONS or action in ("AttachVolume", "DetachVolume"):
        ids = find_all(rp, "instanceId")
        if action in EC2_INSTANCE_ACTIONS and not ids:
            return set(ANY)
        for i in ids:
            arn = ec2_id_arn(i, w)
            if not arn:
                return set(ANY)
            out.add(arn)
    if action in EC2_VOLUME_ACTIONS:
        v = _str(rp.get("volumeId"))
        arn = ec2_id_arn(v, w)
        if not arn:
            return set(ANY)
        out.add(arn)
    if action in EC2_SG_ACTIONS:
        arn = ec2_id_arn(_str(rp.get("groupId")), w)
        if not arn:
            return set(ANY)
        out.add(arn)
    if action in ("CreateTags", "DeleteTags"):
        ids = find_all(rp.get("resourcesSet") or {}, "resourceId")
        if not ids:
            return set(ANY)
        for i in ids:
            arn = ec2_id_arn(i, w)
            if not arn:
                return set(ANY)
            out.add(arn)
    return out or set(ANY)


def _ecr(action, rp, detail, w):
    if action in ("GetAuthorizationToken",):
        return set(ANY)
    names = [_str(rp.get("repositoryName"))] if _str(rp.get("repositoryName")) else []
    names += _strs(rp.get("repositoryNames"))
    registry = _str(rp.get("registryId"))
    if not re.fullmatch(r"\d{12}", registry):
        registry = None
    out = {w.arn("ecr", f"repository/{literal(n)}", account=registry) for n in names}
    return out or set(ANY)


def _cloudformation(action, rp, detail, w):
    if action in ("ListStacks", "ValidateTemplate", "DescribeAccountLimits",
                  "ListExports", "ListImports", "EstimateTemplateCost"):
        return set(ANY)
    name = _str(rp.get("stackName"))
    m = re.match(r"arn:[\w-]+:cloudformation:([\w-]+):(\d{12}):stack/([^/]+)/", name)
    if m:
        return {w.arn("cloudformation", f"stack/{literal(m.group(3))}/*", m.group(1),
                      m.group(2))}
    if name and re.fullmatch(r"[A-Za-z][\w-]*", name):
        return {w.arn("cloudformation", f"stack/{name}/*")}
    return set(ANY)


def _states(action, rp, detail, w):
    out = set()
    for key in ("stateMachineArn", "executionArn", "activityArn"):
        v = _str(rp.get(key))
        if v.startswith("arn:") and ":states:" in v:
            out.add(literal(v))
    return out or set(ANY)


def _sts(action, rp, detail, w):
    if action == "AssumeRole":
        v = _str(rp.get("roleArn"))
        if v.startswith("arn:") and ":role/" in v:
            return {literal(v)}
    return set(ANY)


RESOURCE_RULES = {"s3": _s3, "dynamodb": _dynamodb, "lambda": _lambda, "sqs": _sqs,
                  "sns": _sns, "kms": _kms, "secretsmanager": _secretsmanager, "ssm": _ssm,
                  "logs": _logs, "iam": _iam, "ec2": _ec2, "ecr": _ecr,
                  "cloudformation": _cloudformation, "states": _states, "sts": _sts}


def resources_for(prefix: str, action: str, detail: dict, w: Where) -> set:
    """The resources one call touched, as ARNs a policy can name, or {"*"}."""
    rule = RESOURCE_RULES.get(prefix)
    if rule is None:
        return set(ANY)
    try:
        out = rule(action, _params(detail), detail, w)
    except (AttributeError, TypeError, ValueError):
        return set(ANY)
    return set(ANY) if not out or "*" in out else out


# ---- actions an event needs that CloudTrail doesn't record as their own event

# (service, event): (where the request parameters hold the role, the service it's passed to).
# A place is a key at the top, "a.b" for a key inside an object, or "a[].b" for a key in each
# item of a list. Only those exact places count: a tag or an environment variable that happens
# to be called "role" isn't a role being passed.
PASSROLE_EVENTS = {
    ("lambda", "CreateFunction"): (("role",), "lambda.amazonaws.com"),
    ("lambda", "UpdateFunctionConfiguration"): (("role",), "lambda.amazonaws.com"),
    ("ecs", "RegisterTaskDefinition"): (("taskRoleArn", "executionRoleArn"),
                                        "ecs-tasks.amazonaws.com"),
    ("cloudformation", "CreateStack"): (("roleARN",), "cloudformation.amazonaws.com"),
    ("cloudformation", "UpdateStack"): (("roleARN",), "cloudformation.amazonaws.com"),
    ("cloudformation", "CreateChangeSet"): (("roleARN",), "cloudformation.amazonaws.com"),
    ("states", "CreateStateMachine"): (("roleArn",), "states.amazonaws.com"),
    ("states", "UpdateStateMachine"): (("roleArn",), "states.amazonaws.com"),
    ("glue", "CreateJob"): (("role",), "glue.amazonaws.com"),
    ("glue", "CreateCrawler"): (("role",), "glue.amazonaws.com"),
    ("codebuild", "CreateProject"): (("serviceRole",), "codebuild.amazonaws.com"),
    ("codebuild", "UpdateProject"): (("serviceRole",), "codebuild.amazonaws.com"),
    ("events", "PutTargets"): (("targets[].roleArn",), "events.amazonaws.com"),
    ("eks", "CreateCluster"): (("roleArn",), "eks.amazonaws.com"),
    ("eks", "CreateNodegroup"): (("nodeRole",), ""),
    ("sagemaker", "CreateNotebookInstance"): (("roleArn",), "sagemaker.amazonaws.com"),
    ("sagemaker", "CreateTrainingJob"): (("roleArn",), "sagemaker.amazonaws.com"),
    ("config", "PutConfigurationRecorder"): (("configurationRecorder.roleARN",),
                                             "config.amazonaws.com"),
    ("logs", "PutSubscriptionFilter"): (("roleArn",), ""),
    ("iam", "AddRoleToInstanceProfile"): (("roleName",), ""),
}
# These pass the role inside an instance profile, which the event doesn't name.
INSTANCE_PROFILE_EVENTS = {("ec2", "RunInstances"), ("ec2", "AssociateIamInstanceProfile"),
                           ("ec2", "ReplaceIamInstanceProfileAssociation")}


def values_at(rp: dict, place: str) -> list:
    """The strings at one place in the request parameters, like "roleArn",
    "configurationRecorder.roleARN" or "targets[].roleArn"."""
    items = [rp]
    for part in place.split("."):
        each = part.endswith("[]")
        key = part[:-2] if each else part
        found = [it.get(key) for it in items if isinstance(it, dict)]
        items = [x for v in found if isinstance(v, list) for x in v] if each else found
    return [v for v in items if isinstance(v, str) and v]


def implied_for(prefix: str, event: str, detail: dict, w: Where) -> list:
    """[(action, resources, passed_to_service)] for permissions a call needs on top of its own."""
    rp = _params(detail)
    out = []
    spec = PASSROLE_EVENTS.get((prefix, event))
    if spec:
        keys, service = spec
        roles = set()
        for key in keys:
            for v in values_at(rp, key):
                if re.match(r"arn:[\w-]+:iam::\d{12}:role/", v):
                    roles.add(literal(v))
                elif NAME_RE.fullmatch(v):
                    roles.add(f"arn:{w.partition}:iam::{w.account}:role/{v}")
        if roles:
            out.append(("iam:PassRole", roles, service))
    if (prefix, event) in INSTANCE_PROFILE_EVENTS and (
            rp.get("iamInstanceProfile") or event != "RunInstances"):
        out.append(("iam:PassRole", set(ANY), "ec2.amazonaws.com"))
    if (prefix, event) == ("sts", "AssumeRole"):
        target = _sts("AssumeRole", rp, detail, w)
        if rp.get("tags") or rp.get("transitiveTagKeys"):
            out.append(("sts:TagSession", target, ""))
        if rp.get("sourceIdentity"):
            out.append(("sts:SetSourceIdentity", target, ""))
    return out


@dataclass
class Mapped:
    status: str                              # ok, skip, unmapped
    reason: str = ""
    uses: list = field(default_factory=list)       # [(action, resources)]
    implied: list = field(default_factory=list)    # [(action, resources, passed_to)]
    prefix: str = ""
    event: str = ""


def where_of(detail: dict, principal: Principal | None = None) -> Where:
    ident = detail.get("userIdentity") if isinstance(detail.get("userIdentity"), dict) else {}
    partition = _partition_of(str(ident.get("arn") or "")) if ident.get("arn") else (
        principal.partition if principal else "aws")
    account = str(detail.get("recipientAccountId") or ident.get("accountId") or
                  (principal.account if principal else "") or "")
    return Where(literal(partition), literal(str(detail.get("awsRegion") or "us-east-1")),
                 literal(account))


def map_event(detail: dict, principal: Principal | None = None) -> Mapped:
    """Work out the IAM action(s) and resources one CloudTrail record needed."""
    etype = str(detail.get("eventType") or "")
    if etype in SKIP_EVENT_TYPES:
        return Mapped("skip", SKIP_EVENT_TYPES[etype])
    if detail.get("eventCategory") == "Insight":
        return Mapped("skip", "CloudTrail Insights events")
    source = str(detail.get("eventSource") or "")
    host = source[:-len(".amazonaws.com")] if source.endswith(".amazonaws.com") else source
    name = str(detail.get("eventName") or "")
    if host in SKIP_SOURCES:
        return Mapped("skip", SKIP_SOURCES[host])
    if not host or not name:
        return Mapped("unmapped", "The event has no source or name.", event=name)
    if host in UNMAPPABLE_SERVICES:
        return Mapped("unmapped", UNMAPPABLE_SERVICES[host], prefix=host, event=name)
    prefix = SERVICE_PREFIX.get(host) or (host if host in KNOWN_SERVICES else "")
    if not prefix:
        return Mapped("unmapped", f"{source} isn't in the service table, so its IAM "
                      "prefix isn't known for sure.", prefix=host, event=name)
    event = strip_version(name)
    if (prefix, event) in NO_PERMISSION:
        return Mapped("skip", "calls that need no permission", prefix=prefix, event=event)
    if (prefix, event) in UNMAPPABLE_EVENTS:
        return Mapped("unmapped", UNMAPPABLE_EVENTS[(prefix, event)], prefix=prefix, event=event)
    if not _ACTION_NAME.fullmatch(event):
        return Mapped("unmapped", "The event name doesn't look like an API call.",
                      prefix=prefix, event=name)
    w = where_of(detail, principal)
    uses = []
    for action in ACTION_MAP.get((prefix, event), [event]):
        uses.append((f"{prefix}:{action}", resources_for(prefix, action, detail, w)))
    if (prefix, event) == ("s3", "CopyObject") or (prefix, event) == ("s3", "UploadPartCopy"):
        src = unquote(_str(_params(detail).get("x-amz-copy-source"))).lstrip("/")
        bucket = literal(src.split("/", 1)[0]) if "/" in src else ""
        uses.append(("s3:GetObject", {f"arn:{w.partition}:s3:::{bucket}/*"} if bucket
                     else set(ANY)))
    return Mapped("ok", uses=uses, implied=implied_for(prefix, event, detail, w),
                  prefix=prefix, event=event)


# =================================================================== collecting

@dataclass
class Use:
    action: str
    origin: str = "events"      # events, implied, denied, last-accessed
    resources: set = field(default_factory=set)
    calls: int = 0
    last: datetime | None = None
    regions: set = field(default_factory=set)
    passed_to: str = ""         # iam:PassedToService for an implied iam:PassRole
    needed_by: set = field(default_factory=set)
    errors: Counter = field(default_factory=Counter)
    message: str = ""           # why the latest denied call was denied

    @property
    def service(self) -> str:
        return self.action.split(":", 1)[0]

    @property
    def name(self) -> str:
        return self.action.split(":", 1)[-1]

    def add(self, resources, when, region):
        self.resources |= set(resources)
        self.calls += 1
        if isinstance(when, datetime) and (self.last is None or when > self.last):
            self.last = when
        if region:
            self.regions.add(region)


@dataclass
class Activity:
    principal: Principal
    used: dict = field(default_factory=dict)        # action -> Use
    implied: dict = field(default_factory=dict)     # (action, passed_to) -> Use
    denied: dict = field(default_factory=dict)      # action -> Use
    unmapped: dict = field(default_factory=dict)    # (source, event) -> dict
    skipped: Counter = field(default_factory=Counter)
    others: int = 0             # events from other roles and users
    matched: int = 0
    assumed: int = 0
    sessions: dict = field(default_factory=dict)    # session name -> last time
    first: datetime | None = None
    last: datetime | None = None
    data_events: bool = False
    accounts: Counter = field(default_factory=Counter)
    kinds: Counter = field(default_factory=Counter)

    def services_used(self) -> set:
        return {u.service for u in self.used.values()}


def _later(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


def denied_text(ev) -> str:
    """Why a call was denied, as short as the error message allows."""
    if not isinstance(ev.error_message, str):
        return ""
    text = trail.explain_denied(ev) or ev.error_message.strip()
    if "Encoded authorization failure message" in text:
        text = (text.split("Encoded authorization failure message")[0].strip() +
                " Run aws sts decode-authorization-message on the encoded message to see why.")
    return text


def collect(events, principal: Principal) -> Activity:
    """Sort parsed events (trail.Event) into used, denied and unmapped calls. Pure logic."""
    act = Activity(principal)
    seen = set()
    for ev in events:
        # Records from files are untrusted, so every field is checked for its type.
        d = ev.raw if isinstance(ev.raw, dict) else {}
        eid = d.get("eventID") or ev.event_id
        if eid and isinstance(eid, str):
            if eid in seen:
                act.skipped["events read twice"] += 1
                continue
            seen.add(eid)
        when = ev.time if isinstance(ev.time, datetime) else None
        if when is not None and when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        mine = is_principal(principal, d)
        session = assumed_session(principal, d)
        if session is not None and not mine:
            # Someone assumed the role. That's how sessions are found, not a call it made.
            if session:
                act.assumed += 1
                act.sessions[session] = _later(act.sessions.get(session), when)
            continue
        if not mine:
            act.others += 1
            continue
        act.matched += 1
        if when is not None:
            act.first = when if act.first is None else min(act.first, when)
            act.last = _later(act.last, when)
        kind, _, account, _ = identity_of(d)
        act.kinds[kind] += 1
        if account:
            act.accounts[account] += 1
        if d.get("eventCategory") == "Data" or d.get("managementEvent") is False:
            act.data_events = True
        m = map_event(d, principal)
        if m.status == "skip":
            act.skipped[m.reason] += 1
            continue
        code = ev.error if isinstance(ev.error, str) else str(ev.error or "")
        region = ev.region if isinstance(ev.region, str) else ""
        if code in AUTH_FAILURE_CODES:
            act.skipped["calls with bad or expired credentials"] += 1
            continue
        denied = is_denied_code(code)
        if m.status == "unmapped":
            key = (str(d.get("eventSource") or ""), str(d.get("eventName") or ""))
            row = act.unmapped.setdefault(key, {"source": key[0], "event": key[1], "calls": 0,
                                                "denied": 0, "last": None, "why": m.reason})
            row["calls"] += 1
            row["denied"] += 1 if denied else 0
            row["last"] = _later(row["last"], when)
            continue
        bucket = act.denied if denied else act.used
        for action, res in m.uses:
            use = bucket.get(action)
            if use is None:
                use = bucket[action] = Use(action, "denied" if denied else "events")
            use.add(res, when, region)
            if denied:
                use.errors[code] += 1
                if use.last == when:
                    use.message = denied_text(ev)
        if not denied:
            for action, res, passed_to in m.implied:
                use = act.implied.get((action, passed_to))
                if use is None:
                    use = act.implied[(action, passed_to)] = Use(action, "implied",
                                                                 passed_to=passed_to)
                use.add(res, when, region)
                use.needed_by.add(f"{m.prefix}:{m.event}")
    return act


# =================================================================== reading Event history

@dataclass
class ReadInfo:
    source: str = "aws"             # aws or files
    mode: str = "quick"             # quick, thorough, user, files
    regions: list = field(default_factory=list)
    start: datetime | None = None
    end: datetime | None = None
    days: int = DEFAULT_DAYS
    events_read: int = 0
    cap: int = DEFAULT_CAP
    cap_hit: bool = False
    cancelled: bool = False
    sessions: list = field(default_factory=list)
    sessions_found: int = 0
    regions_failed: list = field(default_factory=list)
    files_read: int = 0
    files: list = field(default_factory=list)
    notes: list = field(default_factory=list)


class _Pacer:
    """Keeps LookupEvents calls in one region at least LOOKUP_INTERVAL apart, measured from
    when each call actually went out."""

    def __init__(self):
        self.lock = threading.Lock()
        self.last = {}

    def wait(self, region):
        while True:
            with self.lock:
                now = time.monotonic()
                due = self.last.get(region, now - LOOKUP_INTERVAL) + LOOKUP_INTERVAL
                if now >= due:
                    self.last[region] = now
                    return
                delay = due - now
            time.sleep(delay)


class _Reader:
    def __init__(self, ctx, start, end, cap, cancel, progress):
        self.ctx, self.start, self.end, self.cap = ctx, start, end, cap
        self.cancel, self.progress = cancel, progress
        self.lock = threading.Lock()
        self.read = 0
        self.cap_hit = False
        self.pacer = _Pacer()
        self.errors = {}     # region -> exception
        self.done = 0
        self.total = 0

    def stopped(self) -> bool:
        return self.cap_hit or (self.cancel is not None and self.cancel.is_set())

    def take(self) -> bool:
        with self.lock:
            if self.read >= self.cap:
                self.cap_hit = True
                return False
            self.read += 1
            return True

    def tick(self, text):
        with self.lock:
            self.done += 1
            done, total, read = self.done, self.total, self.read
        if self.progress:
            self.progress(done, total, f"{text}, {read:,} events read")

    def page_read(self, region):
        """A long read shows its count going up, not just when a region finishes."""
        if self.progress:
            with self.lock:
                done, total, read = self.done, self.total, self.read
            self.progress(done, total, f"Reading {region}, {read:,} events read so far")

    def lookup(self, region, attr=None, value=None) -> list:
        """One LookupEvents query in one region, every page, newest first."""
        ct = self.ctx.client("cloudtrail", region)
        kwargs = {"StartTime": self.start, "EndTime": self.end,
                  "PaginationConfig": {"PageSize": PAGE_SIZE}}
        if attr:
            kwargs["LookupAttributes"] = [{"AttributeKey": attr, "AttributeValue": value}]
        pages = iter(ct.get_paginator("lookup_events").paginate(**kwargs))
        found = []
        while not self.stopped():
            self.pacer.wait(region)
            try:
                page = next(pages)
            except StopIteration:
                break
            for ev in page.get("Events") or []:
                if not self.take():
                    break
                found.append(trail.parse_event(ev, region))
            if page.get("NextToken"):
                self.page_read(region)
        return found

    def run_regions(self, regions, work):
        """work(region) in a few threads at once. Returns {region: events}."""
        out = {}
        if not regions:
            return out
        with ThreadPoolExecutor(max_workers=min(LOOKUP_THREADS, len(regions))) as pool:
            futures = {pool.submit(work, r): r for r in regions}
            for fut in as_completed(futures):
                out[futures[fut]] = fut.result()
        return out

    def guarded(self, region, fn):
        """Run fn(); a failure is kept for the notes, and that region stops there."""
        if region in self.errors or self.stopped():
            return []
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            self.errors.setdefault(region, exc)
            return []


def _region_note(region, exc, profile) -> str:
    code = error_code(exc)
    if is_access_denied(exc):
        return f"{region}: no permission to read Event history (cloudtrail:LookupEvents)."
    if code in ("OptInRequired", "UnrecognizedClientException", "InvalidClientTokenId"):
        return f"{region}: AWS didn't accept the credentials there. Is the region turned on?"
    if code in ("ThrottlingException", "Throttling", "RequestLimitExceeded"):
        return f"{region}: Event history kept saying slow down, so it stopped early there."
    return f"{region}: couldn't read Event history: {error_text(exc, profile)}"


def read_aws(ctx, principal: Principal, regions, start, end, thorough=False,
             cap=DEFAULT_CAP, progress=None, cancel=None) -> tuple:
    """Read the principal's events from Event history. Returns (events, ReadInfo)."""
    regions = sorted(set(regions))
    info = ReadInfo("aws", "thorough" if thorough else "quick", regions, start, end, cap=cap)
    reader = _Reader(ctx, start, end, cap, cancel, progress)
    events = []

    if principal.kind == "user":
        info.mode = "user"
        reader.total = len(regions)

        def user_work(region):
            got = reader.guarded(region, lambda: reader.lookup(region, "Username", principal.name))
            reader.tick(f"Read {region}")
            return got
        for got in reader.run_regions(regions, user_work).values():
            events += got
    elif thorough:
        reader.total = len(regions)

        def all_work(region):
            got = reader.guarded(region, lambda: reader.lookup(region))
            reader.tick(f"Read every event in {region}")
            return got
        for got in reader.run_regions(regions, all_work).values():
            events += got
    else:
        # 1. Where the role was assumed: the role's ARN is a resource of those events.
        reader.total = len(regions)

        def assume_work(region):
            got = reader.guarded(region, lambda: reader.lookup(region, "ResourceName",
                                                               principal.arn))
            reader.tick(f"Finding sessions in {region}")
            return got
        for got in reader.run_regions(regions, assume_work).values():
            events += got
        sessions = {}
        for ev in events:
            name = assumed_session(principal, ev.raw)
            if name:
                sessions[name] = _later(sessions.get(name), ev.time)
        names = sorted(sessions, key=lambda n: (-(sessions[n].timestamp()
                                                  if isinstance(sessions[n], datetime) else 0), n))
        info.sessions_found = len(names)
        if len(names) > MAX_SESSIONS:
            info.notes.append(f"Found {len(names):,} session names and read the newest "
                              f"{MAX_SESSIONS}. Use Thorough to read every event instead.")
            names = names[:MAX_SESSIONS]
        info.sessions = names
        # 2. What each session did, in every region (a session can call any region).
        reader.done = 0
        reader.total = len(regions) * len(names)

        def session_work(region):
            got = []
            for name in names:
                if reader.stopped() or region in reader.errors:
                    break
                got += reader.guarded(region, lambda n=name: reader.lookup(region, "Username", n))
                reader.tick(f"{region}: session {name}")
            return got
        if names:
            for got in reader.run_regions(regions, session_work).values():
                events += got

    info.events_read = reader.read
    info.cap_hit = reader.cap_hit
    info.cancelled = cancel is not None and cancel.is_set()
    for region in sorted(reader.errors):
        info.regions_failed.append(region)
        info.notes.append(_region_note(region, reader.errors[region], ctx.profile))
    if reader.errors and len(reader.errors) == len(regions) and not events:
        region = min(reader.errors)
        first = reader.errors[region]
        if isinstance(first, AuthError):
            raise first
        raise LeastPrivError("Couldn't read Event history in any of the regions. " +
                             _region_note(region, first, ctx.profile))
    return events, info


# =================================================================== reading files

def _mb(n) -> str:
    return f"{n / (1024 * 1024):g} MB"


class _Budget:
    def __init__(self):
        self.used = 0


class TooBig(LeastPrivError):
    """A file over the size limit, or over what's left of the total."""


def _open_regular(path: Path):
    """(open file, size) for a regular file. Anything else is refused before it's read: a
    named pipe would wait forever and a device never ends. O_NONBLOCK keeps the open itself
    from waiting on a pipe; it changes nothing for a regular file."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(str(path), flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise LeastPrivError("isn't a regular file.")
        return os.fdopen(fd, "rb"), st.st_size
    except BaseException:
        os.close(fd)
        raise


def read_capped(path: Path, limit=None) -> bytes:
    """A file's bytes, gunzipped if needed, refusing anything bigger than limit once
    unpacked. Reads at most limit + 1 bytes, so a gzip bomb never gets unpacked."""
    limit = MAX_FILE_BYTES if limit is None else limit
    fh, size = _open_regular(path)
    with fh:
        gzipped = fh.read(2) == b"\x1f\x8b"
        fh.seek(0)
        if gzipped:
            try:
                with gzip.GzipFile(fileobj=fh, mode="rb") as gz:
                    data = gz.read(limit + 1)
            except (OSError, EOFError, zlib.error) as exc:
                raise LeastPrivError(f"isn't a readable gzip file ({exc}).") from None
        else:
            if size > limit:
                raise TooBig(f"is over {_mb(limit)}.")
            data = fh.read(limit + 1)
    if len(data) > limit:
        raise TooBig(f"is over {_mb(limit)} once unpacked.")
    return data


FILE_SUFFIXES = (".json", ".json.gz", ".gz")


def expand_paths(paths, info: ReadInfo) -> list:
    """Files to read, in a stable order. Folders are walked, keeping .json, .json.gz and .gz
    files. Inside a folder, links (to files or folders) aren't followed and anything that
    isn't a plain file is left out, so a planted link can't pull in a file from elsewhere and
    a named pipe can't hang the read. Paths named directly are read as given."""
    out = []
    skipped = links = special = total = 0
    for raw in paths:
        p = Path(raw).expanduser()
        if p.is_dir():
            for root, dirs, files in os.walk(p, followlinks=False):
                dirs.sort()
                for name in sorted(files):
                    if not name.lower().endswith(FILE_SUFFIXES):
                        skipped += 1
                        continue
                    path = Path(root) / name
                    try:
                        mode = os.lstat(path).st_mode
                    except OSError:
                        continue
                    if stat.S_ISLNK(mode):
                        links += 1
                    elif not stat.S_ISREG(mode):
                        special += 1
                    else:
                        total += 1
                        if len(out) < MAX_FILES:
                            out.append(path)
        elif p.is_file():
            total += 1
            if len(out) < MAX_FILES:
                out.append(p)
        elif p.exists():
            info.notes.append(f"{raw}: not a file or a folder.")
        else:
            info.notes.append(f"{raw}: not found.")
    if skipped:
        info.notes.append(f"Skipped {skipped:,} file(s) that aren't .json or .json.gz.")
    if links:
        info.notes.append(f"Skipped {links:,} link(s) inside the folder. Open the files they "
                          "point to directly if you want them read.")
    if special:
        info.notes.append(f"Skipped {special:,} item(s) that aren't plain files, like named "
                          "pipes.")
    if total > MAX_FILES:
        info.notes.append(f"Read the first {MAX_FILES:,} of {total:,} files.")
    return out


def records_in(obj) -> tuple:
    """(kind, items) from parsed JSON: lookup events (with CloudTrailEvent) or raw records."""
    if isinstance(obj, dict) and isinstance(obj.get("Records"), list):
        return "records", obj["Records"]
    if isinstance(obj, dict) and isinstance(obj.get("Events"), list):
        return "lookup", obj["Events"]
    if isinstance(obj, dict) and "eventName" in obj:
        return "records", [obj]
    if isinstance(obj, list):
        if obj and all(isinstance(x, dict) and "CloudTrailEvent" in x for x in obj):
            return "lookup", obj
        if obj and all(isinstance(x, dict) and "eventName" in x for x in obj):
            return "records", obj
    return "", []


def iter_file_events(paths, info: ReadInfo, keep=None, cancel=None):
    """Yield trail.Event for each CloudTrail event in the files. keep(record) can drop raw
    records before they're parsed, which is much faster for big trail folders. A record
    that can't be read as an event is skipped and counted in the notes, so one odd record
    doesn't stop the rest."""
    budget = _Budget()
    files = expand_paths(paths, info)
    roots = [Path(p).expanduser() for p in paths]
    bad = 0
    for path in files:
        if cancel is not None and cancel.is_set():
            info.cancelled = True
            break
        label = path.name
        for root in roots:
            try:
                label = str(path.relative_to(root)) if root.is_dir() else path.name
                break
            except ValueError:
                continue
        room = MAX_TOTAL_BYTES - budget.used
        if room <= 0:
            info.notes.append(f"Stopped at {label}: read {_mb(MAX_TOTAL_BYTES)} of files, "
                              "which is the limit.")
            break
        try:
            data = read_capped(path, min(MAX_FILE_BYTES, room))
        except TooBig as exc:
            if room < MAX_FILE_BYTES:
                info.notes.append(f"Stopped at {label}: the files add up to more than "
                                  f"{_mb(MAX_TOTAL_BYTES)}, which is the limit.")
                break
            info.notes.append(f"{label} {exc} Skipped.")
            continue
        except LeastPrivError as exc:
            info.notes.append(f"{label} {exc} Skipped.")
            continue
        except OSError as exc:
            info.notes.append(f"{label}: couldn't read it ({exc.strerror or exc}).")
            continue
        budget.used += len(data)
        try:
            obj = json.loads(data.decode("utf-8-sig"))
        except UnicodeDecodeError:
            info.notes.append(f"{label} isn't UTF-8 text. Skipped.")
            continue
        except RecursionError:
            info.notes.append(f"{label} is nested too deeply to be CloudTrail events. Skipped.")
            continue
        except ValueError as exc:
            line = getattr(exc, "lineno", None)
            info.notes.append(f"{label} isn't valid JSON" + (f" (line {line})" if line else "") +
                              ". Skipped.")
            continue
        del data
        kind, items = records_in(obj)
        if not kind:
            if not (isinstance(obj, dict) and "digestStartTime" in obj):  # digest files
                info.notes.append(f"{label} doesn't hold CloudTrail events. Skipped.")
            continue
        info.files_read += 1
        info.files.append(label)
        for item in items:
            if not isinstance(item, dict):
                continue
            info.events_read += 1
            try:
                if kind == "lookup":
                    ev = trail.parse_event(item, "")
                    if not ev.raw:          # CloudTrailEvent missing or not a JSON object
                        bad += 1
                        continue
                    wanted = keep is None or keep(ev.raw)
                else:
                    wanted = keep is None or keep(item)
                    ev = trail.parse_event({"CloudTrailEvent": json.dumps(item)},
                                           str(item.get("awsRegion") or "")) if wanted else None
            except (AttributeError, TypeError, ValueError, RecursionError):
                bad += 1
                continue
            if wanted:
                yield ev
    if bad:
        info.notes.append(f"Skipped {bad:,} record(s) that couldn't be read as CloudTrail "
                          "events.")


def principals_in_files(paths) -> Counter:
    """How many events each role and IAM user has in the files."""
    counts = Counter()
    info = ReadInfo("files", "files")

    def count(rec):
        kind, name, account, _ = identity_of(rec)
        if kind and NAME_RE.fullmatch(name):
            counts[(kind, name, account)] += 1
        return False
    for _ in iter_file_events(paths, info, keep=count):
        pass
    return counts


def pick_principal(paths) -> Principal:
    counts = principals_in_files(paths)
    if not counts:
        raise LeastPrivError("No calls by a role or IAM user found in those files.")
    if len(counts) == 1:
        (kind, name, account), _ = counts.most_common(1)[0]
        return Principal(kind, name, "", account)
    top = ", ".join(f"{name} ({n:,} events)" for (_, name, _), n in counts.most_common(5))
    raise LeastPrivError(f"These files have events from {len(counts)} roles and users. Name the "
                         f"one to draft a policy for: {top}" +
                         (" and more." if len(counts) > 5 else "."))


def read_files(paths, principal: Principal, progress=None, cancel=None) -> tuple:
    """Read a principal's events from CloudTrail files and sort them as they come in, so a
    big folder is never held in memory all at once. Returns (Activity, ReadInfo)."""
    info = ReadInfo("files", "files")

    def keep(rec):
        return is_principal(principal, rec) or assumed_session(principal, rec) is not None

    def events():
        for n, ev in enumerate(iter_file_events(paths, info, keep=keep, cancel=cancel), 1):
            yield ev
            if progress and n % 500 == 0:
                progress(0, 0, f"Read {info.files_read:,} file(s), {info.events_read:,} events")
            if cancel is not None and cancel.is_set():
                info.cancelled = True
                break
    activity = collect(events(), principal)
    if not info.files_read and not info.cancelled:
        raise LeastPrivError("None of those files could be read as CloudTrail events. " +
                             " ".join(info.notes[:3]))
    return activity, info


def one_principal(principal: Principal, activity) -> None:
    """A bare name read from files can match more than one role or user: the same role name
    in two accounts (an organization trail), or a role and an IAM user. Mixing their calls
    would draft a policy for calls this one never made, so ask which one is meant."""
    if not principal.kind and len(activity.kinds) > 1:
        raise LeastPrivError(f"The files have calls by both a role and an IAM user named "
                             f"{principal.name}. Say which with role/{principal.name} or "
                             f"user/{principal.name}.")
    if not principal.account and len(activity.accounts) > 1:
        kind = principal.kind or next(iter(activity.kinds), "") or "role"
        accounts = sorted(activity.accounts)
        shown = ", ".join(accounts[:5]) + (" and more" if len(accounts) > 5 else "")
        raise LeastPrivError(f"The files have calls by {principal.name} in {len(accounts)} "
                             f"accounts ({shown}). Name the one you mean with its ARN, like "
                             f"arn:aws:iam::{accounts[0]}:{kind}/{principal.name}.")


# =================================================================== what it has now

@dataclass
class Current:
    policies: list = field(default_factory=list)   # {name, kind, arn, doc, findings}
    services: list | None = None                    # IAM last accessed, or None
    notes: list = field(default_factory=list)

    def docs(self) -> list:
        return [p["doc"] for p in self.policies if isinstance(p.get("doc"), dict)]


def _decode_doc(doc):
    if isinstance(doc, str):
        return json.loads(unquote(doc))
    return doc


def _entity_policies(ctx, iam, entity, name, cur, via=""):
    param = {"role": "RoleName", "user": "UserName", "group": "GroupName"}[entity]
    try:
        for ap in paginate(iam, f"list_attached_{entity}_policies", "AttachedPolicies",
                           **{param: name}):
            entry = {"name": ap.get("PolicyName", ""), "kind": "managed",
                     "arn": ap.get("PolicyArn", ""), "via": via, "doc": None, "findings": []}
            try:
                entry["doc"], _, _ = iampolicy.fetch_policy(ctx, ap["PolicyArn"])
            except Exception as exc:  # noqa: BLE001
                cur.notes.append(f"Couldn't read the policy {entry['name']}: "
                                 f"{error_text(exc, ctx.profile)}")
            cur.policies.append(entry)
    except Exception as exc:  # noqa: BLE001
        cur.notes.append(f"Couldn't list the {entity}'s attached policies: "
                         f"{error_text(exc, ctx.profile)}")
    try:
        for pname in paginate(iam, f"list_{entity}_policies", "PolicyNames", **{param: name}):
            entry = {"name": pname, "kind": "inline", "arn": "", "via": via, "doc": None,
                     "findings": []}
            try:
                resp = getattr(iam, f"get_{entity}_policy")(**{param: name, "PolicyName": pname})
                entry["doc"] = _decode_doc(resp.get("PolicyDocument"))
            except Exception as exc:  # noqa: BLE001
                cur.notes.append(f"Couldn't read the inline policy {pname}: "
                                 f"{error_text(exc, ctx.profile)}")
            cur.policies.append(entry)
    except Exception as exc:  # noqa: BLE001
        cur.notes.append(f"Couldn't list the {entity}'s inline policies: "
                         f"{error_text(exc, ctx.profile)}")


def last_accessed(ctx, arn, cancel=None, wait=None) -> tuple:
    """IAM's last accessed report at action level: (services, note). services is None when
    it couldn't be read."""
    wait = LAST_ACCESSED_WAIT if wait is None else wait
    iam = ctx.client("iam")
    try:
        job = iam.generate_service_last_accessed_details(
            Arn=arn, Granularity="ACTION_LEVEL")["JobId"]
        deadline = time.monotonic() + wait
        delay = POLL_START
        while True:
            resp = iam.get_service_last_accessed_details(JobId=job)
            status = resp.get("JobStatus")
            if status == "COMPLETED":
                break
            if status == "FAILED":
                why = (resp.get("Error") or {}).get("Message") or "no reason given"
                return None, f"IAM couldn't build the last accessed report: {why}"
            if time.monotonic() + delay > deadline:
                return None, (f"IAM hadn't finished the last accessed report after {wait} "
                              "seconds, so unused services aren't shown. Try again in a minute.")
            if cancel is not None:
                if cancel.wait(delay):
                    return None, "Stopped before IAM's last accessed report was ready."
            else:
                time.sleep(delay)
            delay = min(delay * 1.5, 4.0)
        services = list(resp.get("ServicesLastAccessed") or [])
        pages = 0
        while resp.get("IsTruncated") and resp.get("Marker") and pages < 50:
            resp = iam.get_service_last_accessed_details(JobId=job, Marker=resp["Marker"])
            services += resp.get("ServicesLastAccessed") or []
            pages += 1
        return services, ""
    except Exception as exc:  # noqa: BLE001
        if is_access_denied(exc):
            return None, ("No permission for IAM last accessed data (iam:GenerateService"
                          "LastAccessedDetails and iam:GetServiceLastAccessedDetails), so "
                          "unused services aren't shown.")
        return None, f"Couldn't read IAM last accessed data: {error_text(exc, ctx.profile)}"


def fetch_current(ctx, principal: Principal, progress=None, cancel=None) -> Current:
    """The principal's policies now, and IAM's last accessed data for it."""
    cur = Current()
    iam = ctx.client("iam")
    if progress:
        progress(0, 0, f"Reading the {principal.kind}'s current policies...")
    if principal.kind == "user":
        _entity_policies(ctx, iam, "user", principal.name, cur)
        try:
            for g in paginate(iam, "list_groups_for_user", "Groups", UserName=principal.name):
                _entity_policies(ctx, iam, "group", g["GroupName"], cur, via=g["GroupName"])
        except Exception as exc:  # noqa: BLE001
            cur.notes.append(f"Couldn't list the user's groups: {error_text(exc, ctx.profile)}")
    else:
        _entity_policies(ctx, iam, "role", principal.name, cur)
    for p in cur.policies:
        if isinstance(p.get("doc"), dict):
            try:
                p["findings"] = iampolicy.analyze(p["doc"], "identity")
            except Exception:  # noqa: BLE001
                p["findings"] = []
    if cancel is not None and cancel.is_set():
        return cur
    if progress:
        progress(0, 0, "Asking IAM when it last used each service...")
    cur.services, note = last_accessed(ctx, principal.arn, cancel)
    if note:
        cur.notes.append(note)
    return cur


def list_roles(ctx) -> list:
    """The account's roles for the picker, without service-linked ones."""
    out = []
    for r in paginate(ctx.client("iam"), "list_roles", "Roles"):
        if str(r.get("Path", "")).startswith("/aws-service-role/"):
            continue
        out.append({"name": r["RoleName"], "arn": r["Arn"], "path": r.get("Path", "/")})
    out.sort(key=lambda r: r["name"].lower())
    return out


# =================================================================== the draft

@dataclass
class Options:
    specific: bool = True              # scope resources; off gives Resource "*"
    include_denied: bool = False
    include_last_accessed: bool = True


SERVICE_TITLES = {"s3": "S3", "dynamodb": "DynamoDB", "lambda": "Lambda", "sqs": "SQS",
                  "sns": "SNS", "kms": "KMS", "secretsmanager": "SecretsManager", "ssm": "SSM",
                  "logs": "Logs", "cloudwatch": "CloudWatch", "iam": "IAM", "ec2": "EC2",
                  "sts": "STS", "tag": "Tagging", "ecr": "ECR", "ecs": "ECS", "eks": "EKS",
                  "cloudformation": "CloudFormation", "states": "StepFunctions", "ses": "SES",
                  "events": "EventBridge", "rds": "RDS", "acm": "ACM", "elasticloadbalancing":
                  "ELB", "cloudtrail": "CloudTrail", "xray": "XRay", "ce": "CostExplorer",
                  "route53": "Route53", "cloudfront": "CloudFront", "glue": "Glue",
                  "athena": "Athena", "codebuild": "CodeBuild", "ssmmessages": "SSMMessages",
                  "ec2messages": "EC2Messages", "kinesis": "Kinesis", "firehose": "Firehose",
                  "apigateway": "APIGateway", "organizations": "Organizations"}
READ_VERBS = ("Get", "List", "Describe", "Lookup", "Search", "Scan", "Query", "BatchGet",
              "Select", "Filter", "View", "Read", "Head")
TYPE_WORDS = {"s3-bucket": "Buckets", "s3-object": "Objects", "table": "Tables",
              "function": "Functions", "key": "Keys", "secret": "Secrets",
              "parameter": "Parameters", "log-group": "LogGroups", "role": "Roles",
              "user": "Users", "instance": "Instances", "security-group": "SecurityGroups",
              "volume": "Volumes", "repository": "Repositories", "stack": "Stacks",
              "policy": "Policies", "": "Resources"}
ID_TYPES = {"key", "instance", "security-group", "volume", "snapshot", "image",
            "network-interface", "subnet", "vpc", "route-table", "internet-gateway",
            "natgateway", "network-acl", "launch-template", "elastic-ip", "vpc-endpoint",
            "transit-gateway", "dhcp-options", "managed-instance"}
SINGULAR = {"s3-bucket": "Bucket", "s3-object": "Objects", "table": "Table",
            "function": "Function", "key": "Key", "secret": "Secret", "parameter": "Parameter",
            "log-group": "Logs", "role": "Role", "user": "User", "instance": "Instance",
            "security-group": "SecurityGroup", "volume": "Volume", "repository": "Repo",
            "stack": "Stack", "policy": "Policy", "topic": "Topic", "queue": "Queue"}


def camel(text: str, limit=40) -> str:
    words = [w for w in re.split(r"[^A-Za-z0-9]+", text or "") if w]
    out = "".join(w[:1].upper() + w[1:] for w in words)
    return out[:limit]


def split_arn(arn: str):
    """(group key, type, name, rebuild(name) -> ARN) for wildcard collapse and Sids.
    None for "*" or anything that isn't an ARN."""
    parts = arn.split(":", 5)
    if len(parts) < 6 or parts[0] != "arn":
        return None
    _, p, svc, region, account, res = parts
    if svc == "s3":
        if "/" in res:
            bucket = res.split("/", 1)[0]
            return ((p, svc, "", "", "s3-object"), "s3-object", bucket,
                    lambda n: f"arn:{p}:s3:::{n}/*")
        return ((p, svc, "", "", "s3-bucket"), "s3-bucket", res, lambda n: f"arn:{p}:s3:::{n}")
    head = f"arn:{p}:{svc}:{region}:{account}:"
    m = re.match(r"([a-z][a-z-]*)([/:])(.+)$", res)
    if m and svc not in ("sqs", "sns"):
        typ, sep, name = m.groups()
        if svc == "logs" and typ == "log-group" and name.endswith(":*"):
            name = name[:-2]
        return ((p, svc, region, account, typ + sep), typ, name,
                lambda n, h=head + typ + sep: h + n)
    typ = {"sqs": "queue", "sns": "topic"}.get(svc, "")
    return ((p, svc, region, account, ""), typ, res, lambda n, h=head: h + n)


def collapse(resources: set) -> tuple:
    """More than COLLAPSE_AT resources of one type in one account and region become one
    wildcard. Names that share a prefix of 4 or more characters keep it. Returns
    (resources, notes)."""
    if "*" in resources:
        return {"*"}, []
    groups = {}
    loose = set()
    for r in resources:
        info = split_arn(r)
        if info is None:
            loose.add(r)
            continue
        key, typ, name, rebuild = info
        groups.setdefault(key, (typ, rebuild, []))[2].append((name, r))
    out = set(loose)
    notes = []
    for key in sorted(groups):
        typ, rebuild, items = groups[key]
        if len(items) <= COLLAPSE_AT:
            out |= {r for _, r in items}
            continue
        names = sorted(n for n, _ in items)
        prefix = os.path.commonprefix(names).rstrip("*?")
        # Don't cut a ${*} written by literal() in half: a lone "${" would start a variable.
        prefix = re.sub(r"\$(\{[*?$]?)?$", "", prefix)
        if typ in ID_TYPES or key[1] in ("ec2", "kms") or len(prefix) < 4:
            prefix = ""
        wild = rebuild(prefix + "*")
        out.add(wild)
        notes.append((len(items), wild))
    return out, notes


def is_read(action_name: str) -> bool:
    return action_name.startswith(READ_VERBS)


def _resource_hint(resources) -> str:
    if resources == ["*"]:
        return ""
    infos = [split_arn(r) for r in resources]
    if any(i is None for i in infos):
        return ""
    types = {i[1] for i in infos}
    if len(resources) == 1:
        _, typ, name, _ = infos[0]
        word = SINGULAR.get(typ, camel(typ))
        many = TYPE_WORDS.get(typ, camel(typ) + "s")
        base = re.sub(r"-\?{6}$", "", name)
        wild = "*" in base or "?" in base
        stem = base.split("*")[0].split("?")[0]
        if typ in ID_TYPES:
            return "All" + many if wild else word
        if not stem.strip("/:-_. "):
            return "All" + many
        if typ == "function":
            stem = stem.split(":")[0]
        if wild:
            return camel(stem, 32) + many
        return camel(stem, 32) + (word if typ in ("s3-bucket", "s3-object", "table") else "")
    if len(types) == 1:
        return TYPE_WORDS.get(types.pop(), "Resources")
    return "Resources"


def _sid(origin, service, actions, resources, passed_to) -> str:
    title = SERVICE_TITLES.get(service) or camel(service)
    if origin == "implied" and actions == ["iam:PassRole"]:
        to = passed_to.replace(".amazonaws.com", "") if passed_to else ""
        return "IAMPassRole" + ("To" + camel(to) if to else "")
    names = [a.split(":", 1)[1] for a in actions]
    if len(names) == 1:
        middle = names[0]
    else:
        middle = "Read" if all(is_read(n) for n in names) else "Access"
    sid = title + middle + _resource_hint(resources)
    if origin == "denied":
        sid = "PreviouslyDenied" + sid
    elif origin == "last-accessed":
        sid = "LastAccessed" + sid
    return re.sub(r"[^A-Za-z0-9]", "", sid)[:60] or "Statement"


ORIGIN_ORDER = {"events": 0, "implied": 1, "last-accessed": 2, "denied": 3}


def build_policy(uses, specific=True) -> tuple:
    """(policy doc, statement info, collapse notes) from a list of Use. Same uses in any
    order give the same policy."""
    merged = {}   # (group, action, passed_to) -> resources
    for u in uses:
        group = "events" if u.origin in ("events", "implied") else u.origin
        if u.origin == "implied" and u.action == "iam:PassRole":
            group = "implied"
        key = (group, u.action, u.passed_to)
        res = set(u.resources) if specific else {"*"}
        merged.setdefault(key, set()).update(res or {"*"})
    collapsed_notes = []
    statements = {}
    for (group, action, passed_to), res in merged.items():
        res, notes = collapse(res)
        for n, wild in notes:
            collapsed_notes.append(f"{action} touched {n} resources of one type, so the draft "
                                   f"uses {wild} for them.")
        skey = (ORIGIN_ORDER.get(group, 9), group, action.split(":", 1)[0], passed_to,
                tuple(sorted(res)))
        statements.setdefault(skey, set()).add(action)
    out, meta, used_sids = [], [], Counter()
    for skey in sorted(statements, key=lambda k: (k[0], k[2], k[3], k[4] == ("*",), k[4],
                                                  sorted(statements[k]))):
        _, group, service, passed_to, res = skey
        actions = sorted(statements[skey])
        sid = _sid(group, service, actions, list(res), passed_to)
        used_sids[sid] += 1
        if used_sids[sid] > 1:
            sid = f"{sid}{used_sids[sid]}"
        st = {"Sid": sid, "Effect": "Allow", "Action": actions if len(actions) > 1 else actions[0],
              "Resource": list(res) if len(res) > 1 else res[0]}
        if passed_to:
            st["Condition"] = {"StringEquals": {"iam:PassedToService": passed_to}}
        out.append(st)
        meta.append({"sid": sid, "origin": group, "actions": actions})
    return {"Version": "2012-10-17", "Statement": out}, meta, collapsed_notes


def policy_text(doc) -> str:
    return json.dumps(doc, indent=2) + "\n"


def allowed_data_actions(docs) -> list:
    """Data-event actions that these identity policies allow."""
    found = set()
    for doc in docs:
        for st in iampolicy.statements(doc):
            if str(st.get("Effect", "")).capitalize() != "Allow":
                continue
            actions = iampolicy.as_list(st.get("Action"))
            not_actions = iampolicy.as_list(st.get("NotAction"))
            for a in DATA_EVENT_ACTIONS:
                if (actions and iampolicy.grants(actions, a)) or \
                        (not_actions and not iampolicy.grants(not_actions, a)):
                    found.add(a)
    return sorted(found)


def short_resource(arn: str) -> str:
    if arn == "*":
        return "*"
    parts = arn.split(":", 5)
    if len(parts) == 6 and parts[0] == "arn":
        return parts[5]
    return arn


def counts_text(findings) -> str:
    c = Counter(f.severity for f in findings)
    parts = [f"{c[s]} {s}" for s in SEVERITY_ORDER if c.get(s)]
    return ", ".join(parts) if parts else "no findings"


def _plural(n, word, many=None) -> str:
    return f"{n:,} {word if n == 1 else (many or word + 's')}"


@dataclass
class Result:
    principal: Principal
    info: ReadInfo
    activity: Activity
    current: Current | None
    options: Options
    days: int
    window_start: datetime
    doc: dict | None = None
    text: str = ""
    findings: list = field(default_factory=list)
    statements: list = field(default_factory=list)
    included: list = field(default_factory=list)
    from_last_accessed: list = field(default_factory=list)
    collapsed: list = field(default_factory=list)

    # ---- building
    def __post_init__(self):
        self._draft()

    def rebuild(self, options: Options) -> "Result":
        """The same activity drafted with other options. No AWS calls."""
        return Result(self.principal, self.info, self.activity, self.current, options,
                      self.days, self.window_start)

    def _draft(self):
        act = self.activity
        have = {a.lower() for a in act.used} | {u.action.lower() for u in act.implied.values()}
        self.from_last_accessed = []
        for svc in (self.current.services if self.current and self.current.services else []):
            ns = str(svc.get("ServiceNamespace") or "")
            for t in svc.get("TrackedActionsLastAccessed") or []:
                when = t.get("LastAccessedTime")
                name = str(t.get("ActionName") or "")
                if not ns or not name or not isinstance(when, datetime):
                    continue
                if when.tzinfo is None:
                    when = when.replace(tzinfo=timezone.utc)
                if when < self.window_start:
                    continue
                action = name if ":" in name else f"{ns}:{name}"
                if action.lower() in have:
                    continue
                have.add(action.lower())
                use = Use(action, "last-accessed", {"*"}, 0, when,
                          {t["LastAccessedRegion"]} if t.get("LastAccessedRegion") else set())
                self.from_last_accessed.append(use)
        self.from_last_accessed.sort(key=lambda u: u.action)
        uses = list(act.used.values()) + list(act.implied.values())
        if self.options.include_denied:
            uses += list(act.denied.values())
        if self.options.include_last_accessed:
            uses += self.from_last_accessed
        self.included = uses
        if not uses:
            self.doc, self.text, self.findings, self.statements, self.collapsed = \
                None, "", [], [], []
            return
        self.doc, self.statements, self.collapsed = build_policy(uses, self.options.specific)
        self.text = policy_text(self.doc)
        found = iampolicy.analyze(self.doc, "identity")
        found += self._passrole_findings(found)
        self.findings = sorted(found, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))

    def _passrole_findings(self, found) -> list:
        """Policy Check lets iam:PassRole on "*" through when it has an iam:PassedToService
        condition, unless the draft also has an action like ec2:RunInstances. Any role, admin
        ones too, can still be handed to that service (ec2:AssociateIamInstanceProfile puts it
        on a running instance), so the draft's findings say so."""
        flagged = {"iam:PassRole on any role", "PassRole plus a service that runs as a role"}
        if any(f.title in flagged for f in found):
            return []
        for st in self.doc["Statement"]:
            if "iam:PassRole" in iampolicy.as_list(st.get("Action")) and \
                    "*" in iampolicy.as_list(st.get("Resource")):
                return [iampolicy.Finding(
                    "high", "iam:PassRole on any role",
                    "The condition limits it to one service, but any role, including admin "
                    "roles, can be handed to that service.", f"Statement {st['Sid']}",
                    "Put the ARN of the role it passes in Resource.")]
        return []

    # ---- numbers
    def event_actions(self) -> list:
        return sorted(self.activity.used)

    def unused_services(self) -> list:
        """Services the principal's policies allow that it hasn't used in the window, from
        IAM last accessed data. Never-used ones first."""
        if not self.current or self.current.services is None:
            return []
        out = []
        for s in self.current.services:
            when = s.get("LastAuthenticated")
            if isinstance(when, datetime) and when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            if isinstance(when, datetime) and when >= self.window_start:
                continue
            out.append({"service": s.get("ServiceName", ""),
                        "namespace": s.get("ServiceNamespace", ""),
                        "last": when if isinstance(when, datetime) else None,
                        "region": s.get("LastAuthenticatedRegion", "") if when else ""})
        out.sort(key=lambda r: (r["last"] is not None, r["namespace"]))
        return out

    def never_used(self) -> list:
        return [s for s in self.unused_services() if s["last"] is None]

    def window_text(self) -> str:
        if self.info.source == "files":
            return "in the files"
        return "in the last day" if self.days == 1 else f"in the last {self.days} days"

    def now_text(self) -> str:
        if not self.current:
            return ""
        managed = [p for p in self.current.policies if p["kind"] == "managed"]
        inline = [p for p in self.current.policies if p["kind"] == "inline"]
        names = []
        for p in managed:
            names.append(p["name"] + (f" (group {p['via']})" if p.get("via") else ""))
        if len(names) > 3:
            names = names[:3] + [f"{len(managed) - 3} more"]
        text = ", ".join(names)
        if inline:
            text += (" plus " if text else "") + _plural(len(inline), "inline policy",
                                                         "inline policies")
        if not text:
            text = "no policies attached"
        findings = [f for p in self.current.policies for f in p.get("findings", [])]
        checked = [p for p in self.current.policies if p.get("doc")]
        tail = f" Policy Check on those: {counts_text(findings)}." if checked else ""
        return f"Now: {text}.{tail}"

    def summary(self) -> list:
        """Short lines for the top of the page and the terminal."""
        p = self.principal
        acts = self.event_actions()
        services = {a.split(':', 1)[0] for a in acts}
        lines = []
        if self.doc is None:
            lines.append(f"No calls found for {p.label} {self.window_text()}, so there's no "
                         "policy to draft.")
        else:
            n_actions = len({a.lower() for s in self.statements for a in s["actions"]})
            lines.append(f"Draft for {p.label}: {_plural(len(self.statements), 'statement')}, "
                         f"{_plural(n_actions, 'action')}. "
                         f"Policy Check on the draft: {counts_text(self.findings)}.")
        used = f"Used {self.window_text()}: {_plural(len(acts), 'action')} in " \
               f"{_plural(len(services), 'service')}"
        if self.from_last_accessed:
            used += f", plus {len(self.from_last_accessed)} more from IAM last accessed data"
        lines.append(used + ".")
        if self.current:
            lines.append(self.now_text())
            if self.current.services is not None:
                lines.append(f"Allowed but not used in {TRACKING_DAYS} days: "
                             f"{_plural(len(self.never_used()), 'service')}.")
        return lines

    def status_text(self) -> str:
        info = self.info
        where = (f"{_plural(info.files_read, 'file')}" if info.source == "files"
                 else _plural(len(info.regions), "region"))
        acts = len(self.activity.used)
        text = f"{_plural(acts, 'action')} from {self.activity.matched:,} events in {where}."
        if info.cap_hit:
            text += " Stopped at the event cap."
        if info.cancelled:
            text += " Stopped early."
        return text

    def notes(self) -> list:
        info, act = self.info, self.activity
        out = []
        if info.source == "aws":
            span = "the last day" if self.days == 1 else f"the last {self.days} days"
            how = {"quick": f"Quick: {_plural(len(info.sessions), 'session name')} found from "
                            f"{_plural(act.assumed, 'AssumeRole call')}",
                   "thorough": "Thorough: every event in the window, filtered by role",
                   "user": "By user name"}.get(info.mode, info.mode)
            out.append(f"Read {info.events_read:,} events from Event history for {span} in "
                       f"{', '.join(info.regions)}. {how}. Kept {act.matched:,}.")
            if info.mode == "quick" and not info.sessions:
                out.append("No AssumeRole events for this role in those regions and days, so "
                           "no sessions to read. Add the region where it's assumed (STS calls "
                           "often log in us-east-1), widen the window, or try Thorough.")
        else:
            span = ""
            if act.first and act.last:
                span = f", from {local_time(act.first)} to {local_time(act.last)}"
            out.append(f"Read {_plural(info.files_read, 'file')}: {info.events_read:,} events, "
                       f"{act.matched:,} by this {act.principal.kind or 'principal'}{span}. The "
                       "time window isn't applied to files.")
        if info.cap_hit:
            out.append(f"Stopped after reading {info.cap:,} events, the cap. Event history "
                       "returns the newest first, so older calls in the window may be missing. "
                       "Raise the cap or pick a shorter window.")
        if info.cancelled:
            out.append("Stopped early, so this only covers part of the window.")
        out += info.notes
        if act.skipped:
            parts = ", ".join(f"{why} ({n:,})" for why, n in sorted(act.skipped.items()))
            out.append(f"Left out {sum(act.skipped.values()):,} events that a policy doesn't "
                       f"need: {parts}.")
        out += self._data_event_notes()
        out += self._last_accessed_notes()
        for u in sorted(act.implied.values(), key=lambda u: (u.action, u.passed_to)):
            if u.action == "iam:PassRole" and "*" in u.resources:
                out.append(f"{', '.join(sorted(u.needed_by))} passed a role in an instance "
                           "profile, which needs iam:PassRole on that role. The event doesn't "
                           "name the role, so the draft has Resource \"*\". Put the role's ARN "
                           "there.")
        out += self.collapsed
        if "${" in self.text:
            out.append("Some names in the events have *, ? or $ in them, which AWS names almost "
                       "never have. The draft writes them as ${*}, ${?} and ${$}, which IAM "
                       "reads as those characters and not as wildcards, so they can't widen "
                       "it. Check where those calls came from.")
        if self.doc is not None:
            size = len(json.dumps(self.doc, separators=(",", ":")))
            if size > POLICY_SIZE_LIMIT:
                out.append(f"The draft is {size:,} characters without spaces, over the "
                           f"{POLICY_SIZE_LIMIT:,} limit for a managed policy. Split it in two, "
                           "or use an inline policy (10,240 for all of a role's inline "
                           "policies).")
        if self.current:
            out += self.current.notes
        if self.doc is not None:
            out.append("This is a draft to review, not a policy to paste in as is. Try it on a "
                       "test copy of the role first, and watch for AccessDenied in CloudTrail "
                       "after you switch.")
        return out

    def _data_event_notes(self) -> list:
        if self.info.source == "files":
            if self.activity.data_events:
                return [("The files include data events, so object reads and writes, invokes "
                         "and item calls in them are covered.")]
            return [("These files have no data events, so S3 object reads and writes, Lambda "
                     "invokes and DynamoDB item calls aren't covered.")]
        text = ("Event history doesn't record data events: S3 object reads and writes, Lambda "
                "invokes, DynamoDB item calls, SQS messages and SNS publishes.")
        if self.current:
            allowed = allowed_data_actions(self.current.docs())
            if allowed:
                kinds = []
                for a in allowed:
                    if DATA_EVENT_ACTIONS[a] not in kinds:
                        kinds.append(DATA_EVENT_ACTIONS[a])
                shown = ", ".join(kinds)
                text += (f" The current policies allow some of these ({shown}), so the draft "
                         "won't have them unless IAM last accessed data shows them or you read "
                         "trail files that have data events.")
        return [text]

    def _last_accessed_notes(self) -> list:
        if not self.current or not self.current.services:
            return []
        out = []
        seen_services = {u.service for u in self.activity.used.values()} | \
            {u.service for u in self.activity.denied.values()}
        for source, _ in self.activity.unmapped:
            host = source[:-len(".amazonaws.com")] if source.endswith(".amazonaws.com") else source
            seen_services.add(SERVICE_PREFIX.get(host, host))
        regions = set(self.info.regions)
        missing = []
        for s in self.current.services:
            when = s.get("LastAuthenticated")
            ns = s.get("ServiceNamespace", "")
            if not isinstance(when, datetime):
                continue
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            if when >= self.window_start and ns not in seen_services and ns not in ("sts",):
                region = s.get("LastAuthenticatedRegion") or ""
                where = f" in {region}" if region else ""
                hint = " (a region that wasn't read)" if region and self.info.source == "aws" \
                    and region not in regions else ""
                missing.append(f"{ns} on {local_time(when)[:10]}{where}{hint}")
        if missing:
            out.append("IAM says it used these in the window, but no calls to them were read: " +
                       "; ".join(missing[:8]) + (f"; and {len(missing) - 8} more" if
                                                 len(missing) > 8 else "") +
                       ". They may be data events or calls in other regions.")
        if self.from_last_accessed:
            out.append(f"{_plural(len(self.from_last_accessed), 'action')} came from IAM last "
                       "accessed data, which doesn't say on what, so they have Resource \"*\" "
                       "in statements whose Sid starts with LastAccessed. Narrow them by hand.")
        older = [s for s in self.unused_services() if s["last"] is not None]
        if older:
            names = ", ".join(f"{s['namespace']} ({local_time(s['last'])[:10]})"
                              for s in older[:6])
            out.append(f"Used before the window but not in it: {names}"
                       + (" and more" if len(older) > 6 else "") +
                       ". Widen the window if those are still needed.")
        return out

    # ---- rows
    def all_uses(self) -> list:
        act = self.activity
        uses = list(act.used.values()) + list(act.implied.values()) + \
            list(act.denied.values()) + self.from_last_accessed
        return sorted(uses, key=lambda u: (u.service, u.name, ORIGIN_ORDER.get(u.origin, 9),
                                           u.passed_to))

    def use_row(self, u: Use) -> dict:
        included = any(u is x for x in self.included)
        res = sorted(u.resources)
        shown = ", ".join(short_resource(r) for r in res[:3])
        if len(res) > 3:
            shown += f" and {len(res) - 3} more"
        source = {"events": "Event history" if self.info.source == "aws" else "Trail files",
                  "denied": "Denied: " + ", ".join(sorted(u.errors)) if u.errors else "Denied",
                  "last-accessed": "IAM last accessed"}.get(u.origin, "")
        if u.origin == "implied":
            source = "Needed by " + ", ".join(sorted(u.needed_by))
        calls = u.calls if u.origin in ("events", "denied") else None
        calls_text = {"denied": f"{u.calls:,} denied", "implied": "needed",
                      "last-accessed": "last accessed"}.get(u.origin, f"{u.calls:,}")
        return {"service": u.service, "action": u.name, "full": u.action, "resource": shown,
                "resources": res, "calls": calls, "calls_text": calls_text,
                "calls_sort": u.calls, "last": local_time(u.last) if u.last else "",
                "last_date": local_time(u.last)[:10] if u.last else "",
                "last_sort": u.last.isoformat() if u.last else "",
                "result": "Denied" if u.origin == "denied" else (
                    "OK" if u.origin == "events" else ""),
                "source": source, "origin": u.origin, "in_draft": included,
                "message": u.message, "_dim": not included}

    def rows(self) -> list:
        return [self.use_row(u) for u in self.all_uses()]

    def denied_rows(self) -> list:
        return [self.use_row(u) for u in sorted(self.activity.denied.values(),
                                                key=lambda u: u.action)]

    def unmapped_rows(self) -> list:
        out = []
        for row in sorted(self.activity.unmapped.values(), key=lambda r: (r["source"], r["event"])):
            out.append({"source": row["source"], "event": row["event"], "calls": row["calls"],
                        "denied": row["denied"],
                        "last": local_time(row["last"]) if row["last"] else "",
                        "why": row["why"]})
        return out

    def unused_rows(self) -> list:
        return [{"service": s["service"], "namespace": s["namespace"],
                 "last": local_time(s["last"]) if s["last"] else "Not in 400 days",
                 "last_sort": s["last"].isoformat() if s["last"] else "",
                 "region": s["region"]} for s in self.unused_services()]

    def report(self) -> dict:
        """Everything, for --json."""
        def clean(row):
            return {k: v for k, v in row.items() if not k.startswith("_")}
        return {
            "principal": self.principal.as_dict(),
            "source": {"from": self.info.source, "mode": self.info.mode,
                       "regions": self.info.regions, "days": self.days,
                       "start": self.info.start.isoformat() if self.info.start else None,
                       "end": self.info.end.isoformat() if self.info.end else None,
                       "events_read": self.info.events_read, "events_kept": self.activity.matched,
                       "cap": self.info.cap, "cap_hit": self.info.cap_hit,
                       "sessions": self.info.sessions, "files": self.info.files},
            "summary": self.summary(),
            "policy": self.doc,
            "actions": [clean(r) for r in self.rows()],
            "denied": [clean(r) for r in self.denied_rows()],
            "unmapped": self.unmapped_rows(),
            "unused_services": self.unused_rows(),
            "current_policies": [{"name": p["name"], "kind": p["kind"], "arn": p["arn"],
                                  "via": p.get("via", "")}
                                 for p in (self.current.policies if self.current else [])],
            "findings": [f.as_dict() for f in self.findings],
            "notes": self.notes(),
        }


# =================================================================== running it

def default_regions(region) -> list:
    return sorted({region or "us-east-1", "us-east-1"})


def run(profile=None, who="", days=DEFAULT_DAYS, regions=None, thorough=False, files=None,
        compare=None, cap=DEFAULT_CAP, options=None, progress=None, cancel=None,
        ctx=None) -> Result:
    """Read the activity, draft the policy, check it and compare it. Raises LeastPrivError
    or AuthError with a plain message when it can't."""
    options = options or Options()
    days = int(days or DEFAULT_DAYS)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    early_notes = []
    if files:
        principal = parse_principal(who) if (who or "").strip() else pick_principal(files)
        if progress:
            progress(0, 0, "Reading files...")
        activity, info = read_files(files, principal, progress, cancel)
        info.days = days
        one_principal(principal, activity)
        if not principal.account and len(activity.accounts) == 1:
            principal.account = next(iter(activity.accounts))
        if not principal.kind and len(activity.kinds) == 1:
            principal.kind = next(iter(activity.kinds))
        compare = bool(compare)
        if compare:
            try:
                ctx = ctx or AwsContext(profile)
                if principal.account and principal.account != ctx.account:
                    info.notes.append(f"The files are from account {principal.account}, but "
                                      f"this profile is signed in to {ctx.account}, so it "
                                      "didn't compare with what it has now.")
                    compare = False
                else:
                    principal = resolve_principal(ctx, principal, info.notes)
                    activity.principal = principal
            except (AuthError, LeastPrivError) as exc:
                info.notes.append(f"Didn't compare with AWS: {exc}")
                compare = False
            except Exception as exc:  # noqa: BLE001
                info.notes.append(f"Didn't compare with AWS: {error_text(exc, profile)}")
                compare = False
    else:
        if days < 1 or days > 90:
            raise LeastPrivError("Event history keeps 90 days, so pick 1 to 90 days. For "
                                 "older activity, read trail files from S3 instead.")
        compare = True if compare is None else compare
        ctx = ctx or AwsContext(profile)
        principal = resolve_principal(ctx, parse_principal(who), early_notes)
        regions = list(regions or default_regions(ctx.default_region))
        events, info = read_aws(ctx, principal, regions, start, end, thorough, cap,
                                progress, cancel)
        info.days = days
        info.notes = early_notes + info.notes
        activity = collect(events, principal)
    current = None
    if compare and not (cancel is not None and cancel.is_set()):
        current = fetch_current(ctx, principal, progress, cancel)
    return Result(principal, info, activity, current, options, days, start)


# =================================================================== command line

EPILOG = """examples:
  awskit least-priv lab-deployer > policy.json
  awskit least-priv lab-deployer --days 90 -r us-east-1 -r us-west-2
  awskit least-priv arn:aws:iam::111111111111:role/ci-runner --thorough -o ci-runner.json
  awskit least-priv lab-user --include-denied
  awskit least-priv lab-deployer --files ~/trail-logs/ --compare
  awskit least-priv --files events.json          # the files hold only one role

Put ROLE_OR_USER before --files, since --files takes every path after it.
The policy goes to stdout, the summary and notes to stderr, so > policy.json works.
It's a draft: review it and try it on a test role before using it."""


def register_cli(sub, add_profiles):
    import argparse
    p = sub.add_parser("least-priv",
                       help="Draft the smallest IAM policy that covers what a role or user did",
                       description="Reads what a role or IAM user actually called, from "
                       "CloudTrail Event history or\ntrail files, and drafts the smallest IAM "
                       "policy that covers it. Then checks the draft\nwith Policy Check and "
                       "compares it with what the role has now. Read-only.",
                       epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("principal", nargs="?", metavar="ROLE_OR_USER",
                   help="Role or IAM user name, or its ARN. With --files it can be left out "
                        "when the files hold only one.")
    add_profiles(p, many=False)
    p.add_argument("--days", type=int, default=DEFAULT_DAYS, metavar="N",
                   help=f"How many days of Event history to read, 1 to 90 (default {DEFAULT_DAYS})")
    p.add_argument("-r", "--region", action="append",
                   help="Region to read (repeatable). Default: the profile's region plus us-east-1")
    p.add_argument("--thorough", action="store_true",
                   help="Read every event in the window and keep the role's. Slower, but finds "
                        "sessions the quick way can miss")
    p.add_argument("--files", nargs="+", action="extend", metavar="PATH",
                   help="Read CloudTrail files or folders instead: lookup-events output, trail "
                        "log files, .json.gz from S3")
    p.add_argument("--no-resources", action="store_true",
                   help='Use Resource "*" instead of the resources it touched')
    p.add_argument("--include-denied", action="store_true",
                   help="Also add the calls that were denied")
    p.add_argument("--no-last-accessed", action="store_true",
                   help="Leave out actions known only from IAM last accessed data")
    p.add_argument("--compare", dest="compare_on", action="store_true",
                   help="With --files, also compare with the role's current policies in AWS")
    p.add_argument("--no-compare", dest="compare_off", action="store_true",
                   help="Skip reading the current policies and IAM last accessed data")
    p.add_argument("--cap", type=int, default=DEFAULT_CAP, metavar="N",
                   help=f"Most events to read from Event history (default {DEFAULT_CAP:,})")
    p.add_argument("--json", action="store_true",
                   help="Print the whole report as JSON instead of just the policy")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="Write the policy (or the --json report) to FILE")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="No progress line and no notes, just the summary")
    p.set_defaults(func=cmd_least_priv)


_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def plain(text: str) -> str:
    """Text that came from events or file names, safe to print in a terminal: control
    characters, which could move the cursor or set the window title, become ?."""
    return _CONTROL.sub("?", text)


def cmd_least_priv(args) -> int:
    from .cli import err, progress_printer, resolve_profiles
    from .common import color, write_atomic
    if not args.principal and not args.files:
        err("Name a role or IAM user, like: awskit least-priv lab-deployer")
        return 1
    if args.cap < 1:
        err("--cap needs to be 1 or more.")
        return 1
    profile = resolve_profiles(args)[0]
    compare = True if args.compare_on else (False if args.compare_off else None)
    options = Options(specific=not args.no_resources, include_denied=args.include_denied,
                      include_last_accessed=not args.no_last_accessed)
    tty = sys.stderr.isatty()
    show = progress_printer(tty and not args.quiet)

    def progress(done, total, text):
        if total:
            show(done, total, text)
        elif tty and not args.quiet:
            sys.stderr.write(("\r  " + text)[:100].ljust(100))
            sys.stderr.flush()
    try:
        result = run(profile, args.principal or "", args.days, args.region, args.thorough,
                     args.files, compare, args.cap, options, progress)
    except (LeastPrivError, AuthError) as exc:
        _clear_line(tty and not args.quiet)
        err(plain(str(exc)))
        return 1
    except KeyboardInterrupt:
        raise
    except Exception as exc:  # noqa: BLE001
        _clear_line(tty and not args.quiet)
        err(plain(error_text(exc, profile)))
        return 1
    _clear_line(tty and not args.quiet)

    if args.json:
        output = json.dumps(result.report(), indent=2, default=str) + "\n"
    else:
        output = result.text
    if output:
        if args.output:
            try:
                write_atomic(args.output, output)
            except OSError as exc:
                err(f"Couldn't write {args.output}: {exc.strerror or exc}")
                return 1
        else:
            sys.stdout.write(output)
            sys.stdout.flush()

    def say(text, name=None):
        text = plain(text)
        print(color(text, name, tty) if name else text, file=sys.stderr)
    lines = result.summary()
    say(lines[0], "bold")
    for line in lines[1:]:
        say(line)
    if args.output and output:
        say(f"Wrote {args.output}")
    if not args.quiet:
        for f in result.findings:
            head = f"  [{f.severity.upper()}] {f.title}" + (f", {f.where}" if f.where else "")
            say(head, {"critical": "magenta", "high": "red", "medium": "yellow",
                       "low": "blue"}.get(f.severity))
            if f.detail:
                say(f"    {f.detail}")
        denied = result.denied_rows()
        if denied:
            tail = "" if options.include_denied else " (not in the draft, add --include-denied)"
            say(f"Denied{tail}:", "yellow")
            for r in denied:
                say(f"  {r['full']} x{r['calls']} on {r['resource']}" +
                    (f"\n    {r['message'].splitlines()[0]}" if r["message"] else ""))
        unmapped = result.unmapped_rows()
        if unmapped:
            say("Couldn't map these to IAM actions, so add them by hand if needed:", "yellow")
            for r in unmapped:
                say(f"  {r['source']} {r['event']} x{r['calls']}: {r['why']}")
        never = result.never_used()
        if never:
            names = ", ".join(s["namespace"] for s in never[:12])
            say(f"Allowed but not used in {TRACKING_DAYS} days: {names}" +
                (f" and {len(never) - 12} more" if len(never) > 12 else ""))
        notes = result.notes()
        if notes:
            say("Notes:", "dim")
            for n in notes:
                say("  " + n, "dim")
    return 0 if result.doc is not None or args.json else 1


def _clear_line(enabled):
    if enabled:
        sys.stderr.write("\r" + " " * 100 + "\r")
        sys.stderr.flush()


__all__ = ["run", "read_aws", "read_files", "collect", "map_event", "build_policy", "Result",
           "Options", "Principal", "LeastPrivError", "parse_principal", "resolve_principal",
           "fetch_current", "last_accessed", "list_roles", "WINDOWS", "register_cli"]
