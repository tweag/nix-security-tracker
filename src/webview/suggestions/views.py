import logging
from abc import ABC
from typing import Any
from urllib.parse import urlparse

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.paginator import Paginator
from django.db import transaction
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect
from django.urls import resolve, reverse
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
        ).order_by("-updated_at", "-created_at")

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
                "status_filter": self.status_filter,
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
        undo_status_change = request.POST.get(
            "undo_status_change"
        )  # This is set if the status change comes from clicking "Undo"

        # Validate status change
        if not new_status:
            return self._handle_error(request, context, "Missing new status")

        if new_status == suggestion.status:
            return self._handle_error(request, context, "Cannot change to same status")

        # Handle status changes (except publish which needs special handling)
        old_status = suggestion.status  # Will be used for the undo button
        if new_status == "rejected":
            # When undoing a status change, there is no comment form input so we don't expect it
            if not new_comment and not undo_status_change:
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
                    gh_issue_link = create_gh_issue(
                        context["cached_suggestion_raw"],
                        tracker_issue_link,
                        new_comment,
                    ).html_url
                    suggestion.status = CVEDerivationClusterProposal.Status.PUBLISHED
                    suggestion.save()
                    context["issue_link"] = gh_issue_link
            except Exception:
                return self._handle_error(
                    request, context, "Unable to publish this suggestion"
                )

        # Update comment if provided, unless this is an "undo" status change in which no new comment is expected
        if new_comment and not undo_status_change:
            suggestion.comment = new_comment

        suggestion.save()

        # Refresh suggestion context
        context.update(self.get_suggestion_context(suggestion_id))

        # Set target of undo button unless in case of publication
        if new_status != "published":
            context["undo_status_target"] = old_status

        if self._is_origin_url_a_list(request):
            if not undo_status_change:
                # If we come from a suggestion list, we don't update the component in
                # place because the list would mix suggestions of different statuses.
                # Instead, we show only a stub of the suggestion.
                #
                # However, if the status change is an "undo", then we want to show the
                # full suggestion again.
                context["show_stub_only"] = True
        else:
            # If we rerender but we are not in a suggestion list corresponding
            # to a specific status, we want to display the suggestion status so
            # the user can keep track
            context["show_status"] = True

        if request.headers.get("HX-Request"):
            return self.render_to_response(context)
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
        current_url = self._get_origin_url(request)
        if not current_url:
            # Fallback to suggestions list if no origin provided
            logger.error("No origin URL found to redirect to")
            return redirect("webview:suggestions_list")
        return redirect(current_url)

    def _get_origin_url(self, request: HttpRequest) -> str | None:
        current_url = request.headers.get("HX-Current-URL")
        if not current_url:
            current_url = request.META.get("HTTP_REFERER", "")
        return current_url

    def _is_origin_url_a_list(self, request: HttpRequest) -> bool:
        """Checks whether we come from one of the suggestion list views. Returns false when in doubt."""
        origin_url = self._get_origin_url(request)
        if not origin_url:
            return False

        # Extract path from URL
        try:
            # Resolve the URL to get view name
            parsed = urlparse(origin_url)
            resolved = resolve(parsed.path)
            logger.error(resolved)

            # Check if it's one of our list views
            list_url_names = [
                "untriaged_suggestions",
                "draft_suggestions",
                "dismissed_suggestions",
                "published_suggestions",
            ]

            return resolved.url_name in list_url_names
        except Exception:
            return False
