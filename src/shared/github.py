import logging
from urllib.parse import quote

from django.conf import settings
from django.template.defaultfilters import truncatewords
from github import Auth, Github
from github.Issue import Issue as GithubIssue

from shared.models import CachedSuggestions
from shared.models.linkage import CVEDerivationClusterProposal
from webview.templatetags.viewutils import severity_badge

logger = logging.getLogger(__name__)


def get_gh(per_page: int = 30) -> Github:
    """
    Initialize a GitHub API connection
    """

    gh_auth = Auth.AppAuth(
        settings.GH_CLIENT_ID, settings.GH_APP_PRIVATE_KEY
    ).get_installation_auth(settings.GH_APP_INSTALLATION_ID)

    return Github(auth=gh_auth, per_page=per_page)


def create_gh_issue(
    suggestions: list[CVEDerivationClusterProposal],
    title: str,
    tracker_issue_uri: str,
    # FIXME(@fricklerhandwerk): [tag:todo-github-connection] Make an application-level "GitHub connection" object instead.
    # Instantiating the connection at definition time makes mocking it away for tests rather cumbersome.
    # Ideally we'd have a generic mock that would abstract away regular book keeping such as app authentication, and tests would override only relevant behavior.
    github: Github = get_gh(),
) -> GithubIssue:
    """
    Creates a GitHub issue for the given suggestions on the Nixpkgs repository,
    given a link to the corresponding NixpkgsIssue on the tracker side.

    The tracker issue URI could be derived automatically from NixpkgsIssue here,
    but it's more annoying to build without a request object at hand, so we
    leave it to the caller.
    """

    def mention(maintainer: str) -> str:
        """
        Convert a maintainer to a GitHub mention with a leading `@`. If the
        setting GH_ISSUES_PING_MAINTAINERS is set to False, this mention is
        escaped with backticks to prevent actually pinging the maintainers.
        """
        if settings.GH_ISSUES_PING_MAINTAINERS:
            return f"@{maintainer}"
        else:
            return f"`@{maintainer}`"

    def maintainers(suggestion: CVEDerivationClusterProposal) -> str:
        raw = suggestion.cached.payload["categorized_maintainers"]
        # We need to query for the latest username of each maintainer, because
        # those might have changed since they were written out in Nixpkgs; since
        # we have the user id (which is stable), we can ask the GitHub API
        maintainers_list = [
            get_maintainer_username(maintainer, github)
            for maintainer in (raw["active"] + raw["added"])
            if "github_id" in maintainer and "github" in maintainer
        ]
        if maintainers_list:
            maintainers_joined = ", ".join(mention(m) for m in maintainers_list)
            return f"Affected package maintainers: cc {maintainers_joined}\n"
        else:
            return ""

    def affected_nix_packages(suggestion: CVEDerivationClusterProposal) -> str:
        packages = []
        for attribute_name, pkg in suggestion.cached.payload["packages"].items():
            versions = []
            for major_channel, version_data in pkg["channels"].items():
                if version_data["major_version"]:
                    versions.append(f"{version_data['major_version']}@{major_channel}")
            versions_details = f" ({', '.join(versions)})" if versions else ""
            packages.append(f"- `{attribute_name}`{versions_details}")
        return f"""
<details>
<summary>Affected packages</summary>

{"\n".join(packages)}
</details>"""

    def suggestion_comment(suggestion: CVEDerivationClusterProposal) -> str:
        comment = suggestion.comment
        if not comment:
            return ""
        max_backticks = 0
        current_backticks = 0
        for char in comment:
            if char == "`":
                current_backticks += 1
                max_backticks = max(max_backticks, current_backticks)
            else:
                current_backticks = 0
        # Use at least 3 backticks, or one more than the maximum found in
        # order to escape accidents or attempts at escaping the code block
        fence_backticks = "`" * max(3, max_backticks + 1)
        return f"""

### Additional comment

{fence_backticks}
{comment}
{fence_backticks}"""

    def suggestion_section(suggestion: CVEDerivationClusterProposal) -> str:
        cve_id = suggestion.cached.payload["cve_id"]
        section_title = (
            suggestion.cached.payload.get("title")
            or truncatewords(suggestion.cached.payload.get("description", ""), 10)
            or cve_id
        )
        return f"""## {section_title}

- [{cve_id}](https://nvd.nist.gov/vuln/detail/{quote(cve_id)})

{suggestion.cached.payload["description"]}

{affected_nix_packages(suggestion)}

{maintainers(suggestion)}{suggestion_comment(suggestion)}"""

    repo = github.get_repo(f"{settings.GH_ORGANIZATION}/{settings.GH_ISSUES_REPO}")

    sections = "\n\n".join(suggestion_section(s) for s in suggestions)

    body = f"""\
- [Nixpkgs security tracker issue]({tracker_issue_uri})

{sections}"""

    return repo.create_issue(title=title, body=body, labels=settings.GH_ISSUES_LABELS)


def get_maintainer_username(maintainer: dict, github: Github = get_gh()) -> str:
    """
    Get the current GitHub username of a maintainer given their user ID. If the
    request failed, fallback to the github handle stored in the maintainer
    object that comes from Nixpkgs, which might be out of date.
    # TODO: Cache the mapping, e.g. on initial sync and when receiving GitHub events
    # on username change, or simply when doing these calls for resolving the user ID.
    """
    try:
        return github.get_user_by_id(maintainer["github_id"]).login
    except Exception as e:
        logger.error(
            f"Couldn't retrieve the GitHub username for maintainer {maintainer['github_id']}, fallback to {maintainer['github']}: {e}"
        )
        return maintainer["github"]


def fetch_user_info(github_handle: str, github: Github = get_gh()) -> dict | None:
    """
    Fetch GitHub user info by handle.
    """
    try:
        user = github.get_user(github_handle)
        return {
            "id": user.id,
            "login": user.login,
            "name": user.name,
            "email": user.email,
        }
    except Exception:
        logger.error("Could not fetch GitHub user")
        return None
