"""Cloud Map's colors and fonts, in one table.

The draw.io writer reads it now, and the viewer page in AWS Kit will read the same
table, so a map looks the same in both. Dark is based on the D1 diagram. Light uses the
same hues with lighter fills, for READMEs and printing.

Neutral cards (most resources) get a dark card with an AWS-colored icon square. The
identity and CI categories get colored cards like D1, with just the glyph in the card's
text color.
"""
from __future__ import annotations

FONT = "Helvetica"
CONTAINER_TITLE_SIZE = 14
CARD_TITLE_SIZE = 13
CAPTION_SIZE = 11
EDGE_LABEL_SIZE = 10

CATEGORIES = ("identity", "ci", "logging", "network", "compute", "data", "security", "cost",
              "external", "flagged")

# Which category each node kind belongs to. A node can override it with props["category"],
# like a role trusted by GitHub, which is drawn as CI.
KIND_CATEGORY = {
    "user": "identity", "group": "identity", "identity-center": "identity",
    "permission-set": "identity", "saml-provider": "identity", "sso-roles": "identity",
    "idp": "identity",
    "github": "ci", "oidc-provider": "ci",
    "trail": "logging",
    "bucket": "data", "rds": "data",
    "cost": "cost",
    "role": "security", "sg": "security", "nacl": "security",
    "ext-account": "external", "public": "external",
    "instance": "compute",
    "igw": "network", "eigw": "network", "nat": "network", "tgw": "network",
    "tgw-attachment": "network", "endpoint": "network", "lb": "network", "vgw": "network",
    "cgw": "network", "route-table": "network",
}

# The AWS architecture icon colors for each category's icon square.
AWS_ICON = {"logging": "#E7157B", "network": "#8C4FFF", "compute": "#ED7100",
            "data": "#7AA116", "security": "#DD344C", "cost": "#01A88D",
            "external": "#5F5E5A"}


def _card(fill, stroke, title, caption, icon_fill, glyph):
    return {"fill": fill, "stroke": stroke, "title": title, "caption": caption,
            "icon_fill": icon_fill, "glyph": glyph}


def _box(fill, stroke, title, caption, dashed=False, rounded=True, width=1):
    return {"fill": fill, "stroke": stroke, "title": title, "caption": caption,
            "dashed": dashed, "rounded": rounded, "width": width}


def _line(color, width=1.5, dashed=False):
    return {"color": color, "width": width, "dashed": dashed}


def _neutral_cards(fill, stroke, title, caption, external_fill, external_stroke):
    cards = {}
    for cat in ("logging", "network", "compute", "data", "security", "cost"):
        cards[cat] = _card(fill, stroke, title, caption, AWS_ICON[cat], "#FFFFFF")
    cards["external"] = _card(external_fill, external_stroke, title, caption,
                              AWS_ICON["external"], "#FFFFFF")
    return cards


DARK = {
    "page": "#1F1F1E",
    "text": "#F1EFE8",
    "dim": "#B4B2A9",
    "legend_text": "#C2C0B6",
    "footnote": "#8A887F",
    "label_background": "#1F1F1E",
    "containers": {
        "org": _box("#3D3D3A", "#5F5E5A", "#F1EFE8", "#C2C0B6"),
        "ou": _box("none", "#7A7974", "#F1EFE8", "#B4B2A9", dashed=True),
        "account": _box("#1A1A1A", "#444441", "#F1EFE8", "#B4B2A9"),
        "external": _box("none", "none", "#F1EFE8", "#B4B2A9"),
        "identity-center": _box("#2A2560", "#7F77DD", "#EEEDFE", "#CECBF6"),
        "region": _box("none", "#7A7974", "#D3D1C7", "#B4B2A9", dashed=True, rounded=False),
        "vpc": _box("#1E1B29", "#8C4FFF", "#E2D6FF", "#B4B2A9", rounded=False),
        "az": _box("none", "#5F5E5A", "#B4B2A9", "#8A887F", dashed=True),
        "subnet-public": _box("#1B2414", "#7AA116", "#D7E8B5", "#A8B98A", rounded=False),
        "subnet-private": _box("#122326", "#00A4A6", "#B5E3E4", "#8BB7B8", rounded=False),
    },
    "cards": dict(_neutral_cards("#202020", "#444441", "#F1EFE8", "#B4B2A9",
                                 "#2C2C2A", "#888780"),
                  identity=_card("#3C3489", "#7F77DD", "#EEEDFE", "#CECBF6", None, "#CECBF6"),
                  ci=_card("#0F5C4A", "#1D9E75", "#E1F5EE", "#9FE1CB", None, "#9FE1CB")),
    "flagged": {"stroke": "#E24B4A", "fill": "#E24B4A", "text": "#FFFFFF"},
    "edges": {
        "sso": _line("#7F77DD", 2), "saml": _line("#7F77DD", 2),
        "oidc": _line("#1D9E75", 2),
        "trust": _line("#B4B2A9", 1.5), "break-glass": _line("#B4B2A9", 1.5, True),
        "log-delivery": _line("#888780", 1.5),
        "route": _line("#9D6BFF", 1.25), "peering": _line("#8C4FFF", 2),
        "tgw-attachment": _line("#8C4FFF", 2),
        "sg-reference": _line("#EF9F27", 1.25), "vpn": _line("#EF9F27", 2, True),
        "flag": _line("#E24B4A", 2.5),
    },
}

LIGHT = {
    "page": "#FFFFFF",
    "text": "#2C2C2A",
    "dim": "#5F5E5A",
    "legend_text": "#444441",
    "footnote": "#888780",
    "label_background": "#FFFFFF",
    "containers": {
        "org": _box("#F1EFE8", "#D3D1C7", "#2C2C2A", "#5F5E5A"),
        "ou": _box("none", "#B4B2A9", "#2C2C2A", "#5F5E5A", dashed=True),
        "account": _box("#FFFFFF", "#D3D1C7", "#2C2C2A", "#5F5E5A"),
        "external": _box("none", "none", "#2C2C2A", "#5F5E5A"),
        "identity-center": _box("#F5F4FE", "#7F77DD", "#26215C", "#534AB7"),
        "region": _box("none", "#888780", "#444441", "#5F5E5A", dashed=True, rounded=False),
        "vpc": _box("#FAF7FF", "#8C4FFF", "#4B2A99", "#5F5E5A", rounded=False),
        "az": _box("none", "#B4B2A9", "#5F5E5A", "#888780", dashed=True),
        "subnet-public": _box("#F3F8E8", "#7AA116", "#3B5410", "#5B7230", rounded=False),
        "subnet-private": _box("#E8F6F6", "#00A4A6", "#0B4F50", "#2E6E6F", rounded=False),
    },
    "cards": dict(_neutral_cards("#FFFFFF", "#D3D1C7", "#2C2C2A", "#5F5E5A",
                                 "#F1EFE8", "#888780"),
                  identity=_card("#EEEDFE", "#7F77DD", "#26215C", "#534AB7", None, "#534AB7"),
                  ci=_card("#E1F5EE", "#1D9E75", "#04342C", "#0F6E56", None, "#0F6E56")),
    "flagged": {"stroke": "#E24B4A", "fill": "#E24B4A", "text": "#FFFFFF"},
    "edges": {
        "sso": _line("#7F77DD", 2), "saml": _line("#7F77DD", 2),
        "oidc": _line("#1D9E75", 2),
        "trust": _line("#888780", 1.5), "break-glass": _line("#888780", 1.5, True),
        "log-delivery": _line("#B4B2A9", 1.5),
        "route": _line("#8C4FFF", 1.25), "peering": _line("#8C4FFF", 2),
        "tgw-attachment": _line("#8C4FFF", 2),
        "sg-reference": _line("#BA7517", 1.25), "vpn": _line("#BA7517", 2, True),
        "flag": _line("#E24B4A", 2.5),
    },
}

THEMES = {"dark": DARK, "light": LIGHT}


def theme(name: str) -> dict:
    try:
        return THEMES[name]
    except KeyError:
        raise ValueError(f"No theme called {name}. Use dark or light.") from None


def category_of(kind: str, props=None) -> str:
    props = props or {}
    return props.get("category") or KIND_CATEGORY.get(kind, "security")


def card_colors(th: dict, category: str) -> dict:
    return th["cards"].get(category) or th["cards"]["security"]


def container_colors(th: dict, kind: str, props=None) -> dict:
    props = props or {}
    if kind == "subnet":
        kind = "subnet-public" if props.get("public") else "subnet-private"
    return th["containers"].get(kind) or th["containers"]["account"]
