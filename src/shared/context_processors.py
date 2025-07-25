from django.conf import settings
from django.http import HttpRequest


def deployment_info(request: HttpRequest) -> dict[str, str]:
    return {
        "production": settings.PRODUCTION,
        "git_revision": settings.REVISION,
        "show_demo_disclaimer": settings.SHOW_DEMO_DISCLAIMER,
    }
