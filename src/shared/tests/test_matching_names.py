from collections.abc import Callable

import pytest

from shared.matching.names import (
    ecosystem_for,
    ecosystem_package_name,
    go_module_repo,
    normalise_attr,
    normalise_homepage,
    normalise_name,
    normalise_pname,
    normalise_repo,
    package_name_tail,
)
from shared.models.snapshot import BranchPackage

PACKAGES = [
    # (attrpath, pname, homepage)
    (
        "python313Packages.requests",
        "python3.13-requests",
        "http://docs.python-requests.org/",
    ),
    ("perlPackages.DBI", "perl5.42.3-DBI", "https://dbi.perl.org"),
    ("ocamlPackages.lwt", "ocaml5.4.1-lwt", "https://ocsigen.org/lwt/"),
    (
        "lua51Packages.luasocket",
        "lua5.1-luasocket",
        "https://github.com/lunarmodules/luasocket",
    ),
    ("luajitPackages.luasocket", "luajit-2.1-luasocket", None),
    (
        "rPackages.ggplot2",
        "r-ggplot2",
        "https://cran.r-project.org/web/packages/ggplot2/index.html",
    ),
    ("emacsPackages.magit", "emacs-magit", "https://github.com/magit/magit.git"),
    (
        "python313Packages.flask_cors",
        "python3.13-Flask_Cors",
        "https://GitHub.com/CoryDolphin/flask-cors/",
    ),
    ("python-ldap", "python-ldap", "https://WWW.python-ldap.org/#top"),
    ("linuxKernel.packages.linux_6_12.nvidia_x11", "nvidia-x11", None),
    ("openssl_3", "openssl", "https://www.openssl.org/"),
    (
        "teslajsonpy",
        "python3.13-teslajsonpy",
        "https://github.com/zabuldon/teslajsonpy?tab=readme",
    ),
]


def test_sql_and_python_normalisation_agree(
    make_branch_package: Callable[..., BranchPackage],
) -> None:
    for attrpath, pname, homepage in PACKAGES:
        make_branch_package(attrpath=attrpath, pname=pname, homepage=homepage)

    for row in BranchPackage.objects.all():
        assert row.match_pname == normalise_pname(row.pname), row.attrpath
        assert row.match_attr == normalise_attr(row.attrpath), row.attrpath
        assert row.match_homepage == normalise_homepage(row.homepage), row.attrpath


@pytest.mark.parametrize(
    ("pname", "expected"),
    [
        ("python3.13-requests", "requests"),
        ("perl5.42.3-DBI", "dbi"),
        ("lua5.1-luasocket", "luasocket"),
        ("luajit-2.1-luasocket", "luasocket"),
        ("r-ggplot2", "ggplot2"),
        ("python-ldap", "python-ldap"),
        ("Flask_Cors", "flask-cors"),
        ("socket.io", "socket-io"),
    ],
)
def test_normalise_pname(pname: str, expected: str) -> None:
    assert normalise_pname(pname) == expected


def test_normalise_name() -> None:
    assert normalise_name(" Apache HTTP Server ") == "apache-http-server"
    assert normalise_name(None) == ""


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://github.com/Foo/Bar.git", "github.com/foo/bar"),
        ("https://github.com/foo/bar/tree/main/sub", "github.com/foo/bar"),
        ("git@github.com:foo/bar.git", "github.com/foo/bar"),
        ("git://git@gitlab.com:gitlab-org/gitlab.git", "gitlab.com/gitlab-org/gitlab"),
        ("github.com/foo/bar", "github.com/foo/bar"),
        ("https://github.com", None),
        # GitLab projects can be in nested groups.
        (
            "https://gitlab.freedesktop.org/xorg/lib/libxi",
            "gitlab.freedesktop.org/xorg/lib/libxi",
        ),
        (
            "https://gitlab.gnome.org/GNOME/glib/-/tree/main/gio",
            "gitlab.gnome.org/gnome/glib",
        ),
        ("https://gitlab.com/group/-/issues", None),
        (
            "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
            "git.kernel.org/pub/scm/linux/kernel/git/stable/linux",
        ),
    ],
)
def test_normalise_repo(url: str, expected: str | None) -> None:
    assert normalise_repo(url) == expected


def test_ecosystems() -> None:
    pypi = ecosystem_for("https://pypi.org/project/")
    assert pypi is not None and pypi.slug == "pypi"
    assert ecosystem_for("https://access.redhat.com/downloads/") is None
    assert ecosystem_package_name(pypi, "Flask_Cors") == "flask-cors"
    cpan = ecosystem_for("https://cpan.org/modules")
    assert cpan is not None
    assert ecosystem_package_name(cpan, "Class::MethodMaker") == "classmethodmaker"


@pytest.mark.parametrize(
    ("name", "tail"),
    [
        ("org.apache.sshd:sshd-core", "sshd-core"),
        ("github.com/foo/bar/v2", "bar"),
        ("@scope/name", "name"),
        ("requests", None),
    ],
)
def test_package_name_tail(name: str, tail: str | None) -> None:
    assert package_name_tail(name) == tail


def test_go_module_repo() -> None:
    assert go_module_repo("github.com/Foo/bar/v2/sub") == "github.com/foo/bar"
    assert go_module_repo("go.temporal.io/server") is None
