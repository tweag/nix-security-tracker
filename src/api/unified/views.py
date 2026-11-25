from typing import Any, cast

from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response

from api.serializers import ErrorDetailSerializer
from api.suggestions.views import CanEditSuggestion, SuggestionPagination
from api.unified.serializers import (
    ConfirmFixedSerializer,
    PossiblyFixedSerializer,
    StillAffectedSerializer,
)
from shared.derived_state import PossiblyFixed, possibly_fixed_queue, set_verdict
from shared.models.matching import Exposure, Verdict


def _row(p: PossiblyFixed) -> dict[str, Any]:
    last = p.last_affected_evaluation
    return {
        "id": p.exposure_id,
        "suggestion_id": p.suggestion_id,
        "cve_id": p.cve_id,
        "attrpath": p.attrpath,
        "branch": p.branch_id,
        "old_version": p.old_version,
        "new_version": p.new_version,
        "last_affected_commit": last.commit_sha1 if last else None,
        "last_affected_at": last.created_at if last else None,
        "fixed_commit": p.fixed_evaluation.commit_sha1,
        "fixed_at": p.fixed_evaluation.created_at,
        "compare_url": p.compare_url,
    }


class PossiblyFixedViewSet(viewsets.GenericViewSet):
    """
    The "possibly fixed" queue: exposures that were affected and are now observed
    unaffected, without a verdict that answers it. Rows are identified by exposure id.
    """

    serializer_class = PossiblyFixedSerializer
    pagination_class = SuggestionPagination
    queryset = Exposure.objects.none()

    def get_permissions(self) -> list:
        if getattr(self.request, "method", None) != "GET":
            return [IsAuthenticated(), CanEditSuggestion()]
        return []

    @extend_schema(
        operation_id="listPossiblyFixed",
        description=(
            "List the possibly-fixed queue, oldest fix first, paginated. "
            "A row leaves the queue when a verdict answers it: confirmFixed, or stillAffected given after the fix was observed. "
            "It comes back when the attribute is observed affected and then unaffected again."
        ),
        parameters=[
            OpenApiParameter(
                name="branch",
                type=str,
                many=True,
                description="Only rows on these branches (repeatable, combined with OR).",
            )
        ],
        responses={200: PossiblyFixedSerializer(many=True)},
    )
    def list(self, request: Request) -> Response:
        branches = set(request.query_params.getlist("branch"))
        rows = [
            _row(p)
            for p in possibly_fixed_queue()
            if not branches or p.branch_id in branches
        ]
        page = self.paginate_queryset(rows)
        assert page is not None
        return self.get_paginated_response(
            PossiblyFixedSerializer(page, many=True).data
        )

    def _answer(self, pk: int, verdict: str, data: dict, user: User) -> Response:
        exposure = get_object_or_404(
            Exposure.objects.select_related("suggestion", "branch"), pk=pk
        )
        set_verdict(
            exposure.suggestion,
            exposure.attrpath,
            verdict,
            user,
            branch=exposure.branch,
            comment=data.get("comment", ""),
            fix_commit=data.get("fix_commit"),
        )
        return Response(status=204)

    @extend_schema(
        operation_id="confirmPossiblyFixed",
        description="Confirm the fix: write a `fixed` verdict for the row's attribute on its branch.",
        request=ConfirmFixedSerializer,
        responses={
            204: None,
            400: ErrorDetailSerializer,
            403: ErrorDetailSerializer,
            404: ErrorDetailSerializer,
        },
    )
    @action(detail=True, methods=["post"], url_path="confirm_fixed")
    def confirm_fixed(self, request: Request, pk: int) -> Response:
        serializer = ConfirmFixedSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return self._answer(
            pk,
            Verdict.Kind.FIXED,
            cast(dict, serializer.validated_data),
            cast(User, request.user),
        )

    @extend_schema(
        operation_id="stillAffectedPossiblyFixed",
        description="Reject the fix: write an `affected` verdict for the row's attribute on its branch.",
        request=StillAffectedSerializer,
        responses={
            204: None,
            400: ErrorDetailSerializer,
            403: ErrorDetailSerializer,
            404: ErrorDetailSerializer,
        },
    )
    @action(detail=True, methods=["post"], url_path="still_affected")
    def still_affected(self, request: Request, pk: int) -> Response:
        serializer = StillAffectedSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return self._answer(
            pk,
            Verdict.Kind.AFFECTED,
            cast(dict, serializer.validated_data),
            cast(User, request.user),
        )
