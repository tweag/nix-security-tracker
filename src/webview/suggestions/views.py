import logging
from abc import ABC
from typing import Any

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.paginator import Paginator
from django.db import transaction
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.views.generic import TemplateView

from shared.auth import can_publish_github_issue
from shared.github import create_gh_issue
from shared.logs.batches import batch_events
from shared.logs.events import remove_canceling_events
from shared.logs.fetchers import fetch_suggestion_events
from shared.models import (
    NixpkgsIssue,
)
from shared.models.cached import CachedSuggestions
from shared.models.linkage import CVEDerivationClusterProposal

logger = logging.getLogger(__name__)


class SuggestionBaseView(LoginRequiredMixin, TemplateView, ABC):
    """Base view for all suggestion-related views with common functionality."""

    def get_suggestion_context(
        self, suggestion_id_input: str | int | None
    ) -> dict[str, Any]:
        """Get common context data for a suggestion."""
        # Validate provided suggestion id
        if suggestion_id_input is None:
            raise Http404("Suggestion ID is required")
        try:
            suggestion_id_int = int(suggestion_id_input)
        except (ValueError, TypeError):
            raise Http404("Invalid suggestion ID")

        suggestion = get_object_or_404(
            CVEDerivationClusterProposal, id=suggestion_id_int
        )
        cached_suggestion = get_object_or_404(
            CachedSuggestions, proposal_id=suggestion_id_int
        )

        # Get activity log
        raw_events = fetch_suggestion_events(suggestion.pk)
        activity_log = batch_events(remove_canceling_events(raw_events, sort=True))

        return {
            "suggestion": suggestion,
            "cached_suggestion": cached_suggestion.payload,
            # FIXME(@florentc): This is only used in create_gh_issue. We should use payload there too eventually.
            "cached_suggestion_raw": cached_suggestion,
            "activity_log": activity_log,
        }


class SuggestionDetailView(SuggestionBaseView):
    """Individual suggestion detail page."""

    template_name = "suggestions/suggestion_detail.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        suggestion_id = kwargs.get("suggestion_id")  # Could be None if missing

        # Get suggestion context (with proper error handling)
        context = self.get_suggestion_context(suggestion_id)

        return context


class SuggestionListView(SuggestionBaseView, ABC):
    """Base list view for suggestions filtered by a specific status."""

    template_name = "suggestions/suggestion_list.html"
    paginate_by = 20
    status_filter = None  # To be defined in concrete classes

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Get paginated suggestions for the specific status."""
        context = super().get_context_data(**kwargs)

        # Get suggestions with the specific status
        suggestions = CVEDerivationClusterProposal.objects.filter(
            status=self.status_filter
        ).order_by("-created_at")

        for suggestion in suggestions:
            raw_events = fetch_suggestion_events(suggestion.pk)
            suggestion.activity_log = batch_events(
                remove_canceling_events(raw_events, sort=True)
            )

        # Pagination
        paginator = Paginator(suggestions, self.paginate_by)
        page_number = self.request.GET.get("page", 1)
        page_obj = paginator.get_page(page_number)

        context.update(
            {
                "suggestions": page_obj.object_list,
                "page_obj": page_obj,
                "adjusted_elided_page_range": paginator.get_elided_page_range(),
                "is_paginated": True,
            }
        )

        return context


class UntriagedSuggestionsView(SuggestionListView):
    status_filter = CVEDerivationClusterProposal.Status.PENDING


class AcceptedSuggestionsView(SuggestionListView):
    status_filter = CVEDerivationClusterProposal.Status.ACCEPTED


class RejectedSuggestionsView(SuggestionListView):
    status_filter = CVEDerivationClusterProposal.Status.REJECTED


class PublishedSuggestionsView(SuggestionListView):
    status_filter = CVEDerivationClusterProposal.Status.PUBLISHED


class UpdateSuggestionStatusView(SuggestionBaseView):
    """Handle suggestion status changes (accept/reject/publish)."""

    template_name = "suggestions/components/suggestion.html"

    def post(self, request: HttpRequest, suggestion_id: int) -> HttpResponse:
        """Handle status change requests."""
        if not request.user or not can_publish_github_issue(request.user):
            return HttpResponseForbidden()

        # Get suggestion context
        context = self.get_suggestion_context(suggestion_id)
        suggestion = context["suggestion"]

        # Get form data
        new_status = request.POST.get("new_status")
        new_comment = request.POST.get("comment", "").strip()

        # Validate status change
        if not new_status:
            return self._handle_error(request, context, "Missing new status")

        if new_status == suggestion.status:
            return self._handle_error(request, context, "Cannot change to same status")

        # Handle status changes (except publish which needs special handling)
        if new_status == "rejected":
            if not new_comment:
                return self._handle_error(
                    request, context, "You must provide a dismissal comment"
                )
            suggestion.status = CVEDerivationClusterProposal.Status.REJECTED
        elif new_status == "accepted":
            suggestion.status = CVEDerivationClusterProposal.Status.ACCEPTED
        elif new_status == "published":
            try:
                with transaction.atomic():
                    tracker_issue = NixpkgsIssue.create_nixpkgs_issue(suggestion)
                    tracker_issue_link = request.build_absolute_uri(
                        reverse("webview:issue_detail", args=[tracker_issue.code])
                    )
                    _gh_issue_link = create_gh_issue(
                        context["cached_suggestion_raw"],
                        tracker_issue_link,
                        new_comment,
                    ).html_url
                    suggestion.status = CVEDerivationClusterProposal.Status.PUBLISHED
                    suggestion.save()
            except Exception:
                return self._handle_error(
                    request, context, "Unable to publish this suggestion"
                )

        # Update comment if provided
        if new_comment:
            suggestion.comment = new_comment

        suggestion.save()

        # Return appropriate response
        new_context = self.get_suggestion_context(suggestion_id)
        if request.headers.get("HX-Request"):
            return self.render_to_response(new_context)
        else:
            return self._redirect_to_origin(request)

    def _handle_error(
        self, request: HttpRequest, context: dict, error_message: str
    ) -> HttpResponse:
        """Handle error responses for both HTMX and standard requests."""
        context["error_message"] = error_message
        if request.headers.get("HX-Request"):
            return self.render_to_response(context)
        else:
            # Without javascript, we use Django messages for the errors
            messages.error(request, error_message)
            return redirect(reverse("webview:subscriptions:center"))

    def _redirect_to_origin(self, request: HttpRequest) -> HttpResponse:
        # Get the current URL from HTMX header or referer
        current_url = request.headers.get("HX-Current-URL")
        if not current_url:
            current_url = request.META.get("HTTP_REFERER", "")
        if not current_url:
            # Fallback to suggestions list if no origin provided
            logger.error("No origin URL found to redirect to")
            return redirect("webview:suggestions_list")
        return redirect(current_url)
