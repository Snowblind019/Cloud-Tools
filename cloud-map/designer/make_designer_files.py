"""Writes the AWS Kit Designer shape libraries and the example designs. Run it from the
root of the repo after changing how designer shapes look, or the examples:

    python3 cloud-map/designer/make_designer_files.py

The tests check that the committed files match what this writes.
"""
import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from awskit import mapdesign as md  # noqa: E402

EXAMPLES = ROOT / "cloud-map" / "examples"

# The good example: a two-AZ VPC with public and private subnets, a NAT gateway per
# zone, an S3 gateway endpoint, and two security groups with an arrow between them.
GOOD = {
    "name": "two-az-vpc", "region": "us-west-2",
    "vpc": {"id": "vpc", "x": 40, "y": 90, "w": 1100, "h": 560,
            "settings": {"name": "lab", "cidr": "10.0.0.0/16"}},
    "igw": {"id": "igw", "x": 640, "y": -20, "settings": {"name": "lab-igw"}},
    "subnets": [
        {"id": "public-a", "x": 20, "y": 70, "settings": {"name": "public-a", "cidr": "10.0.1.0/24", "az": "a", "type": "public"}},
        {"id": "public-b", "x": 380, "y": 70, "settings": {"name": "public-b", "cidr": "10.0.2.0/24", "az": "b", "type": "public"}},
        {"id": "private-a", "x": 20, "y": 320, "settings": {"name": "private-a", "cidr": "10.0.11.0/24", "az": "a", "type": "private"}},
        {"id": "private-b", "x": 380, "y": 320, "settings": {"name": "private-b", "cidr": "10.0.12.0/24", "az": "b", "type": "private"}},
    ],
    "nats": [
        {"id": "nat-a", "in": "public-a", "x": 30, "y": 80, "settings": {"name": "nat-a", "mode": "per-az"}},
        {"id": "nat-b", "in": "public-b", "x": 30, "y": 80, "settings": {"name": "nat-b", "mode": "per-az"}},
    ],
    "endpoints": [
        {"id": "s3", "x": 780, "y": 70, "settings": {"name": "s3", "kind": "gateway", "service": "s3", "route_tables": "private"}},
    ],
    "sgs": [
        {"id": "web", "x": 780, "y": 190, "settings": {"name": "web", "description": "Load balancer",
                                                     "ingress": "tcp 443 0.0.0.0/0", "egress": "all 0.0.0.0/0"}},
        {"id": "app", "x": 780, "y": 410, "settings": {"name": "app", "description": "App servers",
                                                     "ingress": "", "egress": "all 0.0.0.0/0"}},
    ],
    "arrows": [{"id": "web-to-app", "from": "web", "to": "app", "settings": {"protocol": "tcp", "ports": "8080"}}],
    "notes": [],
}


def cells_for(d, theme="dark"):
    cells = []
    v = d["vpc"]
    if v is not None:
        cells += md.shape_cells("vpc", v["id"], v["x"], v["y"], v["w"], v["h"], v["settings"],
                                theme_name=theme)
    if d.get("igw"):
        g = d["igw"]
        cells += md.shape_cells("igw", g["id"], g["x"], g["y"], settings=g["settings"],
                                parent=g.get("in", "vpc"), theme_name=theme)
    for s in d["subnets"]:
        cells += md.shape_cells("subnet", s["id"], s["x"], s["y"], 340, 220, s["settings"],
                                parent=s.get("in", "vpc"), theme_name=theme)
    for n in d["nats"]:
        cells += md.shape_cells("nat", n["id"], n["x"], n["y"], settings=n["settings"],
                                parent=n["in"], theme_name=theme)
    for e in d["endpoints"]:
        cells += md.shape_cells("endpoint", e["id"], e["x"], e["y"], settings=e["settings"],
                                parent=e.get("in", "vpc"), theme_name=theme)
    for g in d["sgs"]:
        cells += md.shape_cells("sg", g["id"], g["x"], g["y"], settings=g["settings"],
                                parent=g.get("in", "vpc"), theme_name=theme)
    for a in d["arrows"]:
        cells.append(md.arrow_cell(a["id"], a.get("from", ""), a.get("to", ""), a["settings"],
                                   theme_name=theme, src_point=a.get("src_point"),
                                   dst_point=a.get("dst_point")))
    for i, (text, x, y) in enumerate(d.get("notes", [])):
        cells.append(md.note_cell(f"note-{i}", text, x, y, 400, 40, theme))
    return cells


def design(d, theme="dark"):
    return md.design_xml(d["name"], d["region"], theme, cells_for(d, theme), 1180, 700)


def broken():
    """One design per check, each the good one with one thing wrong. The file name says
    what, and the tests look for the message."""
    out = {}

    def make(name, fn):
        d = copy.deepcopy(GOOD)
        d["name"] = name
        fn(d)
        out[name] = d

    def sub(d, sid):
        return next(s for s in d["subnets"] if s["id"] == sid)
    make("bad-cidr", lambda d: d["vpc"]["settings"].update(cidr="10.0.0.0/33"))
    make("subnet-outside-vpc-cidr", lambda d: sub(d, "private-b")["settings"].update(cidr="10.1.12.0/24"))
    make("overlapping-subnets", lambda d: sub(d, "private-b")["settings"].update(cidr="10.0.11.128/25"))
    make("missing-zone", lambda d: sub(d, "private-b")["settings"].update(az=""))
    make("zone-not-in-region", lambda d: sub(d, "private-b")["settings"].update(az="e"))
    make("nat-in-private-subnet", lambda d: d["nats"][1].update({"in": "private-b"}))
    make("private-subnet-without-nat", lambda d: d["nats"].pop(1))
    make("public-subnet-without-igw", lambda d: d.update(igw=None))
    make("bad-security-group-rule", lambda d: d["sgs"][0]["settings"].update(ingress="tcp 99999 0.0.0.0/0"))
    make("arrow-not-between-groups", lambda d: d["arrows"][0].update({"to": "s3"}))
    make("duplicate-names", lambda d: sub(d, "private-b")["settings"].update(name="private-a"))
    make("unsafe-name", lambda d: sub(d, "private-b")["settings"].update(name="private b!"))
    make("bad-description", lambda d: d["sgs"][1]["settings"].update(description="App servers – prod"))

    def outside(d):
        s = sub(d, "private-b")
        s.update({"in": "1", "x": 1200, "y": 420})
    make("subnet-outside-vpc", outside)
    make("no-region", lambda d: d.update(region=""))
    return out


def warnings():
    out = {}
    d = copy.deepcopy(GOOD)
    d["name"] = "single-nat-open-ssh"
    d["nats"] = [{"id": "nat-a", "in": "public-a", "x": 30, "y": 80,
                  "settings": {"name": "nat", "mode": "single"}}]
    d["sgs"][0]["settings"]["ingress"] = "tcp 443 0.0.0.0/0; tcp 22 0.0.0.0/0 # SSH from anywhere"
    out[d["name"]] = d
    d = copy.deepcopy(GOOD)
    d["name"] = "public-only"
    d["subnets"] = d["subnets"][:2]
    d["nats"] = []
    d["endpoints"] = []
    out[d["name"]] = d
    return out


def outputs() -> dict:
    """{path: text} for every file this script writes."""
    files = {
        md.library_path("dark"): md.library_xml("dark"),
        md.library_path("light"): md.library_xml("light"),
        EXAMPLES / "design-two-az-vpc.drawio": design(GOOD),
    }
    for name, d in broken().items():
        files[EXAMPLES / "broken-designs" / f"{name}.drawio"] = design(d)
    for name, d in warnings().items():
        files[EXAMPLES / "broken-designs" / f"warning-{name}.drawio"] = design(d)
    return files


def main():
    for path, text in outputs().items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"Wrote {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
