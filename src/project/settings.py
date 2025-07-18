"""
Django settings for tracker project.

Generated by 'django-admin startproject' using Django 4.2.4.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

import importlib.util
import sys
from os import environ as env
from pathlib import Path
from typing import Annotated

import dj_database_url
import sentry_sdk
from pydantic import BaseModel, DirectoryPath, Field, PlainSerializer
from pydantic_settings import BaseSettings, SettingsConfigDict
from sentry_sdk.integrations.django import DjangoIntegration


class CredentialsDirectory(BaseSettings):
    """
    Configuration for the directory with secret values.
    This is captured separately so we can use it in `secrets_dir`
    to declare the types of values we expect inside.
    """

    # https://systemd.io/CREDENTIALS/
    CREDENTIALS_DIRECTORY: DirectoryPath


class Secrets(BaseSettings):
    """
    Secret values, obtained from `CREDENTIALS_DIRECTORY`.
    While this could be subsumed under general settings, separating it has advantages:
    1. Secrets are configured separately and this allows checking immediately if all values are set.
    2. We can construct default values in regular configuration that depend on secrets.
    """

    model_config = SettingsConfigDict(
        # https://docs.pydantic.dev/latest/concepts/pydantic_settings/#secrets
        secrets_dir=CredentialsDirectory().CREDENTIALS_DIRECTORY,  # type: ignore[reportCallIssue]
    )

    SECRET_KEY: str
    GH_CLIENT_ID: str
    GH_SECRET: str
    GH_WEBHOOK_SECRET: str
    GH_APP_INSTALLATION_ID: int
    GH_APP_PRIVATE_KEY: str


secrets = Secrets()  # type: ignore[reportCallIssue]
get_secret = secrets.model_dump().get


class Settings(BaseSettings):
    # https://docs.pydantic.dev/latest/concepts/pydantic_settings/
    class DjangoSettings(BaseModel):
        # SECURITY WARNING: don't run with debug turned on in production!
        DEBUG: bool = False
        # TODO(@fricklerhandwerk): once we go live, remove this and use only `DEBUG` as the toggle for development mode
        PRODUCTION: bool = True
        REVISION: str = Field(
            description="""
            Git revision of the deployed security tracker.
            """
        )
        STATIC_ROOT: Path = Field(
            description="""
            Writeable directory for compilimg static files, such as stylesheets, when running `manage collectstatic`.
            """
        )
        SYNC_GITHUB_STATE_AT_STARTUP: bool = Field(
            description="""
            Connect to GitHub when the service is started and update
            team membership (security team and committers team)
            of Nixpkgs maintainers in the evaluation database.
            """
        )
        GH_ISSUES_PING_MAINTAINERS: bool = Field(
            description="""
            When set to False, the application will escape package maintainers' name when
            mentioning them in a GitHub issue to avoid actually pinging them.
            This is used as a safety measure during development. Set to True in production.
            """
        )
        GH_ORGANIZATION: str = Field(
            description="""
            The GitHub organisation from which to get team membership.
            Set `NixOS` for the production deployment.
            """
        )
        GH_ISSUES_REPO: str = Field(
            description="""
            The GitHub repository to post issues to when publishing a vulnerability record.
            It must exist in `GH_ORGANIZATION.`
            Set `nixpkgs` for the production deployment.
            """
        )
        GH_SECURITY_TEAM: str = Field(
            description="""
            The GitHub team to use for mapping "security team" (essentially admin) permissions onto users of the security tracker.
            It must exist in `GH_ORGANIZATION.`
            Set `security` for the production deployment.
            """
        )
        GH_COMMITTERS_TEAM: str = Field(
            description="""
            The GitHub team to use for mapping "maintainer" permissions onto users of the security tracker.
            It must exist in `GH_ORGANIZATION.`
            Set `nixpkgs-committers` for the production deployment.
            """
        )
        GH_ISSUES_LABELS: list[str] = Field(
            description="""
            Labels to attach to Github issues created from the tracker, making
            it easier to filter them on the target repository.
            """,
            # It's always ok to operate with an empty list of labels both in
            # production and in development mode. Override accordingly depending
            # on the environment.
            default=[],
        )

        class SocialAccountProviders(BaseModel):
            class GitHub(BaseModel):
                SCOPE: list[str] = Field(
                    description="Access scopes required by the application"
                )

                class AppSettings(BaseModel):
                    client_id: Annotated[str, PlainSerializer(get_secret)]
                    secret: Annotated[str, PlainSerializer(get_secret)]
                    key: str = ""

                APPS: list[AppSettings] = []

            github: GitHub | None

        _GitHub = SocialAccountProviders.GitHub
        _App = SocialAccountProviders.GitHub.AppSettings

        SOCIALACCOUNT_PROVIDERS: SocialAccountProviders = SocialAccountProviders(
            github=_GitHub(
                SCOPE=["read:user", "read:org"],
                APPS=[_App(client_id="GH_CLIENT_ID", secret="GH_SECRET")],
            ),
        )

    DJANGO_SETTINGS: DjangoSettings = Field(
        description="""
        Application settings are configured from a separate environment variable:
        1. To make them distinct from secrets, which have their own configuration mechanism
        2. To avoid collisions with environment variables that may be needed by other processes.
        """,
    )


for key, value in Secrets().model_dump().items():  # type: ignore[reportCallIssue]
    setattr(sys.modules[__name__], key, value)


for key, value in Settings().model_dump()["DJANGO_SETTINGS"].items():  # type: ignore[reportCallIssue]
    setattr(sys.modules[__name__], key, value)

# TODO(@fricklerhandwerk): move all configuration over to pydantic-settings

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

## GlitchTip setup
if "GLITCHTIP_DSN" in env:
    sentry_sdk.init(
        dsn=get_secret("GLITCHTIP_DSN"),
        integrations=[DjangoIntegration()],
        auto_session_tracking=False,
        traces_sample_rate=0,
    )

## Channel setup
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": list(filter(None, [env.get("REDIS_UNIX_SOCKET")])),
        },
    },
}

## Logging settings
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {module} {process:d} {thread:d} {message}",
            "style": "{",
        },
        "simple": {
            "format": "{levelname} {message}",
            "style": "{",
        },
    },
    "filters": {
        "require_debug_true": {
            "()": "django.utils.log.RequireDebugTrue",
        },
    },
    "handlers": {
        "console": {
            "level": "DEBUG" if DEBUG else "INFO",  # type: ignore # noqa: F821
            "filters": ["require_debug_true"],
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
        "console_production": {
            "level": "ERROR",
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
        "mail_admins": {
            "level": "ERROR",
            "class": "django.utils.log.AdminEmailHandler",
        },
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "propagate": True,
        },
        "django.request": {
            "handlers": ["console_production", "mail_admins"],
            "level": "ERROR",
            "propagate": False,
        },
        "django.db.backends": {
            "level": "INFO" if "LOG_DB_QUERIES" not in env else "DEBUG",
            "handlers": ["console"],
        },
        "shared": {
            "handlers": ["console", "console_production", "mail_admins"],
            "level": "DEBUG" if DEBUG else "INFO",  # type: ignore # noqa: F821
            "filters": [],
        },
    },
}
## Evaluation settings

GIT_CLONE_URL = "https://github.com/NixOS/nixpkgs"
# This is the path where a local checkout of Nixpkgs
# will be instantiated for this application's needs.
# By default, in the root of this Git repository.
LOCAL_NIXPKGS_CHECKOUT = (BASE_DIR / ".." / ".." / "nixpkgs").resolve()
# Evaluation concurrency
# Do not go overboard with this, as Nixpkgs evaluation
# is _very_ expensive.
# The more cores you have, the more RAM you will consume.
# TODO(raitobezarius): implement fine-grained tuning on `nix-eval-jobs`.
MAX_PARALLEL_EVALUATION = 3
# Where are stored the evaluation gc roots directory
EVALUATION_GC_ROOTS_DIRECTORY: str = str(
    Path(BASE_DIR / ".." / ".." / "nixpkgs-gc-roots").resolve()
)
# Where are the stderr of each `nix-eval-jobs` stored.
EVALUATION_LOGS_DIRECTORY: str = str(
    Path(BASE_DIR / ".." / ".." / "nixpkgs-evaluation-logs").resolve()
)
CVE_CACHE_DIR: str = str(Path(BASE_DIR / ".." / ".." / "cve-cache").resolve())
# This can be tuned for your specific deployment,
# this is used to wait for an evaluation slot to be available
# It should be around the average evaluation time on your machine.
# in seconds.
# By default: 25 minutes.
DEFAULT_SLEEP_WAITING_FOR_EVALUATION_SLOT = 25 * 60

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = get_secret("SECRET_KEY")

ALLOWED_HOSTS = []

# Application definition
ASGI_APPLICATION = "project.asgi.application"
INSTALLED_APPS = [
    "daphne",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.humanize",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django_filters",
    "debug_toolbar",
    # AllAuth config
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "allauth.socialaccount.providers.github",
    "channels",
    "pgpubsub",
    "pgtrigger",
    "pghistory",
    "pghistory.admin",
    "rest_framework",
    "shared",
    "webview",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "debug_toolbar.middleware.DebugToolbarMiddleware",
    # Allauth account middleware
    "allauth.account.middleware.AccountMiddleware",
    "pghistory.middleware.HistoryMiddleware",
]

ROOT_URLCONF = "project.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "shared/templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "shared.context_processors.git_revision",
            ],
        },
    },
]

WSGI_APPLICATION = "project.wsgi.application"

## Realtime events configuration

# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {}
DATABASES["default"] = dj_database_url.config(conn_max_age=600, conn_health_checks=True)

# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": f"django.contrib.auth.password_validation.{v}"}
    for v in [
        "UserAttributeSimilarityValidator",
        "MinimumLengthValidator",
        "CommonPasswordValidator",
        "NumericPasswordValidator",
    ]
]

AUTHENTICATION_BACKENDS = [
    # Needed to login by username in Django admin, regardless of `allauth`
    "django.contrib.auth.backends.ModelBackend",
    "allauth.account.auth_backends.AuthenticationBackend",
]


REST_FRAMEWORK = {
    "DEFAULT_FILTER_BACKENDS": ["django_filters.rest_framework.DjangoFilterBackend"]
}

SITE_ID = 1

# Disable regular signup but allow GitHub auth
SOCIALACCOUNT_ONLY = True
ACCOUNT_ALLOW_REGISTRATION = False
ACCOUNT_EMAIL_VERIFICATION = "none"

# TODO: make configurable so one can log in locally
LOGIN_REDIRECT_URL = "webview:home"

# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = "en-gb"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = "static/"

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# needed for debug_toolbar
INTERNAL_IPS = [
    "127.0.0.1",
    "[::1]",
]

# This will be synced with GH_COMMITTERS_TEAM in GH_ORGANIZATION.
DB_COMMITTERS_TEAM = "committers"
# This will be synced with GH_SECURITY_TEAM in GH_ORGANIZATION
DB_SECURITY_TEAM = "security_team"

GH_WEBHOOK_SECRET = get_secret("GH_WEBHOOK_SECRET")

TEST_RUNNER = "project.test_runner.CustomTestRunner"

# Make history log immutable by default
PGHISTORY_APPEND_ONLY = True
PGHISTORY_ADMIN_MODEL = "pghistory.MiddlewareEvents"

# Customization via user settings
# This must be at the end, as it must be able to override the above
user_settings_file = env.get("USER_SETTINGS_FILE", None)
if user_settings_file is not None:
    spec = importlib.util.spec_from_file_location("user_settings", user_settings_file)
    if spec is None or spec.loader is None:
        raise RuntimeError("User settings specification failed!")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sys.modules["user_settings"] = module
    from user_settings import *  # noqa: F403 # pyright: ignore [reportMissingImports]

# Settings side-effect, must be after the loading of ALL settings, including user ones.

# Ensure the following directories exist.
Path(EVALUATION_GC_ROOTS_DIRECTORY).mkdir(exist_ok=True)
Path(EVALUATION_LOGS_DIRECTORY).mkdir(exist_ok=True)
