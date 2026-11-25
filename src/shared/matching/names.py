"""
Normalisation of names and URLs shared by the CVE side (Python) and the package
side (generated columns of `BranchPackage`, SQL).

The regular expressions below are written in the common subset of Python `re`
and PostgreSQL ARE so that `normalise_pname` and the `match_pname` column agree;
`test_matching_names.py` checks that they do.
"""

import re
from dataclasses import dataclass

# Prefixes nixpkgs puts in front of the derivation name of language and plugin
# package sets, e.g. `python3.13-requests`, `perl5.42.0-DBI`, `ocaml5.4.1-lwt`,
# `lua5.1-luasocket`, `r-ggplot2`, `emacs-magit`. Measured on a nixos-unstable
# `packages.json` (2026-09) by comparing the derivation name with `meta.pname`.
# Versioned interpreter prefixes require a digit, so `python-ldap` stays intact.
LANGUAGE_PREFIX_RE = (
    r"^("
    r"python[0-9][0-9.]*|perl[0-9][0-9.]*|ocaml[0-9][0-9.]*|ruby[0-9][0-9.]*"
    r"|lua[0-9][0-9.]*|luajit[0-9.-]*|coq[0-9][0-9.]*(-mathcomp[0-9.]*)?"
    r"|rocq[0-9][0-9.]*(-mathcomp[0-9.]*)?|cuda[0-9][0-9.]*|erlang[0-9.]*"
    r"|php|r|emacs|sbcl|chicken|kodi|typst-package|vimplugin(-luajit[0-9.]*)?"
    r"|fishplugin|kakplugin|gimp-plugin|eclipse-plugin|zellij-plugin|roundcube-plugin"
    r")-"
)
# Runs of separators that upstreams and nixpkgs use interchangeably.
SEPARATORS_RE = r"[-_. ]+"
# Everything up to the last dot of an attribute path.
ATTR_PARENT_RE = r"^.*\."
URL_SCHEME_RE = r"^[a-z][a-z0-9+.-]*://(www\.)?"
URL_TAIL_RE = r"(\.git)?/*([?#].*)?$"

_language_prefix = re.compile(LANGUAGE_PREFIX_RE)
_separators = re.compile(SEPARATORS_RE)
_attr_parent = re.compile(ATTR_PARENT_RE)
_url_scheme = re.compile(URL_SCHEME_RE)
_url_tail = re.compile(URL_TAIL_RE)


def normalise_name(value: str | None) -> str:
    """Lowercase, separators unified to `-`, trimmed."""
    return _separators.sub("-", (value or "").strip().lower()).strip("-")


def normalise_pname(pname: str) -> str:
    """`pname` without a language-set prefix, normalised; the `match_pname` column."""
    return normalise_name(_language_prefix.sub("", pname.lower(), count=1))


def normalise_attr(attrpath: str) -> str:
    """Last attribute path component, normalised; the `match_attr` column."""
    return normalise_name(_attr_parent.sub("", attrpath, count=1))


def normalise_homepage(url: str | None) -> str | None:
    """Scheme, `www.`, `.git`, trailing slashes, query and fragment removed, lowercased; the `match_homepage` column."""
    if not url:
        return None
    return _url_tail.sub("", _url_scheme.sub("", url.lower(), count=1), count=1)


# Non-names that CNAs put into `product`; they must not drive name matching.
NON_NAMES = frozenset(
    {
        "",
        "n-a",
        "na",
        "n/a",
        "none",
        "unknown",
        "unspecified",
        "not-applicable",
        "all",
        "various",
        "multiple",
        "other",
        "*",
    }
)

_scp_like = re.compile(r"^(?:[\w.-]+@)?([\w.-]+\.[a-z]{2,}):(.+)$")
# Forges whose URLs are `host/owner/repo[/...]`.
FORGE_HOSTS = frozenset(
    {
        "github.com",
        "gitlab.com",
        "codeberg.org",
        "bitbucket.org",
        "sr.ht",
        "git.sr.ht",
        "gitlab.gnome.org",
        "gitlab.freedesktop.org",
        "invent.kde.org",
        "salsa.debian.org",
        "gitea.com",
    }
)


def normalise_repo(url: str | None) -> str | None:
    """
    Repository URL in the form of `normalise_homepage`, with forge URLs cut to
    `host/owner/repo` and scp-like `git@host:owner/repo.git` rewritten.
    """
    if not url:
        return None
    url = url.strip()
    if "://" not in url:
        if m := _scp_like.match(url):
            url = f"https://{m.group(1)}/{m.group(2)}"
        else:
            url = f"https://{url}"
    elif m := _scp_like.match(url.split("://", 1)[1]):
        url = f"https://{m.group(1)}/{m.group(2)}"
    normalised = normalise_homepage(url)
    if not normalised:
        return None
    host, _, path = normalised.partition("/")
    host = host.rsplit("@", 1)[-1]
    if host in FORGE_HOSTS:
        parts = [p for p in path.split("/") if p]
        if len(parts) < 2:
            return None
        path = "/".join(parts[:2])
        path = _url_tail.sub("", path, count=1)
    return f"{host}/{path}" if path else host


@dataclass(frozen=True)
class Ecosystem:
    """A language package registry and the nixpkgs package sets that mirror it."""

    slug: str  # purl type
    hosts: frozenset[str]
    # Anchored regular expression over the attribute path, or None when nixpkgs has no such set.
    attr_set_re: str | None = None


ECOSYSTEMS = (
    Ecosystem(
        "pypi",
        frozenset({"pypi.org", "pypi.python.org", "files.pythonhosted.org"}),
        r"^python[0-9]*Packages\.",
    ),
    Ecosystem("gem", frozenset({"rubygems.org"}), r"^rubyPackages[0-9_]*\."),
    Ecosystem(
        "npm",
        frozenset({"registry.npmjs.org", "npmjs.com", "npmjs.org"}),
        r"^nodePackages(_latest)?\.",
    ),
    Ecosystem("hex", frozenset({"hex.pm", "repo.hex.pm"}), r"^beamPackages\."),
    Ecosystem(
        "cpan",
        frozenset({"cpan.org", "metacpan.org", "search.cpan.org"}),
        r"^perl[0-9]*Packages\.",
    ),
    Ecosystem("hackage", frozenset({"hackage.haskell.org"}), r"^haskellPackages\."),
    Ecosystem("cran", frozenset({"cran.r-project.org"}), r"^rPackages\."),
    Ecosystem("opam", frozenset({"opam.ocaml.org"}), r"^ocamlPackages\."),
    Ecosystem("luarocks", frozenset({"luarocks.org"}), r"^lua[0-9]*Packages\."),
    Ecosystem("cargo", frozenset({"crates.io"})),
    Ecosystem("golang", frozenset({"pkg.go.dev", "proxy.golang.org", "golang.org"})),
    Ecosystem(
        "maven",
        frozenset({"repo.maven.apache.org", "repo1.maven.org", "central.sonatype.com"}),
    ),
    Ecosystem("composer", frozenset({"packagist.org"})),
    Ecosystem("nuget", frozenset({"nuget.org"})),
)


def ecosystem_for(collection_url: str | None) -> Ecosystem | None:
    """The registry a CVE 5 `collectionURL` names, by host."""
    normalised = normalise_homepage(collection_url)
    if not normalised:
        return None
    host = normalised.split("/", 1)[0]
    for ecosystem in ECOSYSTEMS:
        if host in ecosystem.hosts:
            return ecosystem
    return None


_go_major = re.compile(r"/v[0-9]+$")


def ecosystem_package_name(ecosystem: Ecosystem, package_name: str) -> str:
    """Registry package name in the form nixpkgs uses for its attribute names, normalised."""
    name = package_name.strip()
    if ecosystem.slug == "cpan":
        # `Class::MethodMaker` and `Class-MethodMaker` are `perlPackages.ClassMethodMaker`.
        return re.sub(r"(::|-)", "", name).lower()
    if ecosystem.slug == "npm" and name.startswith("@"):
        name = name.replace("/", "-").lstrip("@")
    return normalise_name(name)


def package_name_tail(package_name: str) -> str | None:
    """
    The last component of a qualified package name, when it has one:
    `org.apache.sshd:sshd-core` (Maven), `github.com/foo/bar/v2` (Go),
    `@scope/name` (npm), `vendor/name` (Composer, Red Hat).
    """
    name = _go_major.sub("", package_name.strip().rstrip("/"))
    tail = re.split(r"[/:]", name)[-1]
    return tail if tail and tail != package_name.strip() else None


def go_module_repo(package_name: str) -> str | None:
    """`github.com/foo/bar/v2/sub` as a normalised repository, for forge-hosted Go modules."""
    parts = package_name.strip().split("/")
    if len(parts) >= 3 and parts[0].lower() in FORGE_HOSTS:
        return normalise_repo("https://" + "/".join(parts[:3]))
    return None


# Package page of a registry, as nixpkgs homepages sometimes give it, in `normalise_homepage` form.
_REGISTRY_PAGES = {
    "pypi": ("pypi.org/project/{}", "pypi.python.org/pypi/{}"),
    "npm": ("npmjs.com/package/{}",),
    "cargo": ("crates.io/crates/{}",),
    "gem": ("rubygems.org/gems/{}",),
    "hex": ("hex.pm/packages/{}",),
    "hackage": ("hackage.haskell.org/package/{}",),
    "cran": ("cran.r-project.org/web/packages/{}", "cran.r-project.org/package={}"),
    "cpan": ("metacpan.org/dist/{}", "metacpan.org/release/{}"),
    "opam": ("opam.ocaml.org/packages/{}",),
    "luarocks": ("luarocks.org/modules/{}",),
    "golang": ("pkg.go.dev/{}",),
    "composer": ("packagist.org/packages/{}",),
    "nuget": ("nuget.org/packages/{}",),
}


def registry_pages(ecosystem: Ecosystem, package_name: str) -> tuple[str, ...]:
    """Normalised URLs of the package's page on its registry."""
    name = package_name.strip().lower()
    if ecosystem.slug == "cpan":
        name = name.replace("::", "-")
    variants = dict.fromkeys(
        [name, name.replace("_", "-"), name.replace("-", "_")]
        if ecosystem.slug == "pypi"
        else [name]
    )
    return tuple(
        page.format(variant)
        for page in _REGISTRY_PAGES.get(ecosystem.slug, ())
        for variant in variants
    )
