from drf_spectacular.utils import OpenApiParameter
from rest_framework.request import Request

ACTIVITY_LOG_PARAMETER = OpenApiParameter(
    name="activity_log",
    type=bool,
    location=OpenApiParameter.QUERY,
    required=False,
    description=(
        "When true, inline each suggestion's activity log in its `activity_log` field instead of requiring a separate request to the activity_log endpoint."
    ),
)


def activity_log_requested(request: Request) -> bool:
    """Whether the `activity_log` query param is truthy on this request."""
    return request.query_params.get("activity_log", "").lower() in ("true", "1", "yes")
