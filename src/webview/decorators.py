"""
Permission decorators for webview classes.

This module contains reusable decorators for common permission checks
to reduce code duplication and centralize authorization logic.
"""

from collections.abc import Callable
from functools import wraps
from typing import Any

from django.http import HttpRequest, HttpResponse, HttpResponseForbidden

from shared.auth import isadmin, ismaintainer


def require_maintainer_or_admin(view_func: Callable) -> Callable:
    """
    Decorator that requires the user to be either a maintainer or admin.

    Returns HttpResponseForbidden if the user doesn't have the required permissions.
    This decorator is intended for use on view methods that handle POST requests
    where permission checking is needed.

    Usage:
        @require_maintainer_or_admin
        def post(self, request, *args, **kwargs):
            # Permission already checked, proceed with logic
            pass
    """

    @wraps(view_func)
    def wrapper(self: Any, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        if not request.user or not (
            isadmin(request.user) or ismaintainer(request.user)
        ):
            return HttpResponseForbidden()
        return view_func(self, request, *args, **kwargs)

    return wrapper
