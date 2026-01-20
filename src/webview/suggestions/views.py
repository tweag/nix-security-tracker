import logging
from abc import ABC, abstractmethod
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
from shared.listeners.cache_suggestions import apply_package_edits, to_dict
from shared.logs.batches import FoldedEventType, batch_events
from shared.logs.events import remove_canceling_events
from shared.logs.fetchers import fetch_suggestion_events
from shared.models import (
    NixpkgsIssue,
)
from shared.models.linkage import (
    CVEDerivationClusterProposal,
    MaintainersEdit,
    PackageEdit,
)
from shared.models.nix_evaluation import NixMaintainer
from webview.suggestions.context.builders import (
    get_maintainer_list_context,
    get_package_list_context,
    is_suggestion_editable,
)
from webview.suggestions.context.types import SuggestionContext, SuggestionStubContext

logger = logging.getLogger(__name__)


class SuggestionBaseView(LoginRequiredMixin, TemplateView, ABC):
    """Base view for all suggestion-related views with common functionality."""

    def fetch_suggestion(self, suggestion_id: int) -> CVEDerivationClusterProposal:
        return get_object_or_404(CVEDerivationClusterProposal, id=suggestion_id)

    def fetch_activity_log(self, suggestion_id: int) -> list[FoldedEventType]:
        raw_events = fetch_suggestion_events(suggestion_id)
        return batch_events(remove_canceling_events(raw_events, sort=True))

    def get_suggestion_context(
        self, suggestion: CVEDerivationClusterProposal
    ) -> SuggestionContext:
        return SuggestionContext(
            suggestion=suggestion,
            package_list_context=get_package_list_context(suggestion),
            maintainer_list_context=get_maintainer_list_context(suggestion),
            activity_log=self.fetch_activity_log(suggestion.pk),
        )

    def _handle_error(
        self,
        request: HttpRequest,
        suggestion_context: SuggestionContext,
        error_message: str,
    ) -> HttpResponse:
        """Handle error responses for both HTMX and standard requests."""
        suggestion_context.error_message = error_message
        if request.headers.get("HX-Request"):
            return self.render_to_response({"data": suggestion_context})
        else:
            # Without javascript, we use Django messages for the errors
            messages.error(request, error_message)
            return self._redirect_to_origin(request)

    def _redirect_to_origin(self, request: HttpRequest) -> HttpResponse:
        """Redirect to the origin URL or fallback to suggestions list."""
        # Get the current URL from HTMX header or referer
        current_url = self._get_origin_url(request)
        if not current_url:
            # Fallback to suggestions list if no origin provided
            logger.error("No origin URL found to redirect to")
            return redirect("webview:suggestion:untriaged_suggestions")
        return redirect(current_url)

    def _get_origin_url(self, request: HttpRequest) -> str | None:
        """Get the origin URL from HTMX headers or HTTP referer."""
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


class SuggestionDetailView(SuggestionBaseView):
    """Individual suggestion detail page."""

    template_name = "suggestions/suggestion_detail.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        suggestion_id_input = kwargs.get("suggestion_id")  # Could be None if missing

        # Validate provided suggestion id
        if suggestion_id_input is None:
            raise Http404("Suggestion ID is required")
        try:
            suggestion_id = int(suggestion_id_input)
            suggestion = get_object_or_404(
                CVEDerivationClusterProposal, id=suggestion_id
            )
            context.update(
                {"suggestion_context": self.get_suggestion_context(suggestion)}
            )
            return context
        except (ValueError, TypeError):  # FIXME(@florentc): also catch db error
            raise Http404("Invalid suggestion ID")


class SuggestionListView(SuggestionBaseView, ABC):
    """Base list view for suggestions filtered by a specific status."""

    template_name = "suggestions/suggestion_list.html"
    paginate_by = 10
    status_filter = None  # To be defined in concrete classes

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Get paginated suggestions for the specific status."""
        context = super().get_context_data(**kwargs)

        # Get suggestions with the specific status
        suggestions = CVEDerivationClusterProposal.objects.filter(
            status=self.status_filter
        ).order_by("-updated_at", "-created_at")

        # Pagination first
        paginator = Paginator(suggestions, self.paginate_by)
        page_number = self.request.GET.get("page", 1)
        page_obj = paginator.get_page(page_number)

        # Convert suggestions to SuggestionContext objects for the current page
        suggestion_contexts = []
        for suggestion in page_obj.object_list:
            suggestion_context = self.get_suggestion_context(suggestion)
            suggestion_contexts.append(suggestion_context)

        context.update(
            {
                "suggestion_contexts": suggestion_contexts,
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
        suggestion = self.fetch_suggestion(suggestion_id)
        suggestion_context = self.get_suggestion_context(suggestion)

        # Get form data
        new_status = request.POST.get("new_status")
        new_comment = request.POST.get("comment", "").strip()
        undo_status_change = request.POST.get(
            "undo_status_change"
        )  # This is set if the status change comes from clicking "Undo"

        # Validate status change
        if not new_status:
            return self._handle_error(request, suggestion_context, "Missing new status")

        if new_status == suggestion.status:
            return self._handle_error(
                request, suggestion_context, "Cannot change to same status"
            )

        # Handle status changes (except publish which needs special handling)
        github_issue_link = None  # Will be used if we publish
        undo_status_target = (
            suggestion.status
        )  # We keep track of the previous status to provide an undo action
        if new_status == "rejected":
            # When undoing a status change, there is no comment form input so we don't expect it
            if not new_comment and not undo_status_change:
                return self._handle_error(
                    request, suggestion_context, "You must provide a dismissal comment"
                )
            suggestion.status = CVEDerivationClusterProposal.Status.REJECTED
        else:
            if new_status == "accepted":
                suggestion.status = CVEDerivationClusterProposal.Status.ACCEPTED
            elif new_status == "published":
                try:
                    with transaction.atomic():
                        tracker_issue = NixpkgsIssue.create_nixpkgs_issue(suggestion)
                        tracker_issue_link = request.build_absolute_uri(
                            reverse("webview:issue_detail", args=[tracker_issue.code])
                        )
                        github_issue_link = create_gh_issue(
                            suggestion_context.suggestion.cached,
                            tracker_issue_link,
                            new_comment,
                        ).html_url
                        suggestion.status = (
                            CVEDerivationClusterProposal.Status.PUBLISHED
                        )
                        suggestion.save()
                        undo_status_target = None  # We disable the undo button in case we have published. There is no turning back.
                except Exception:
                    return self._handle_error(
                        request, suggestion_context, "Unable to publish this suggestion"
                    )

        # Update comment if provided, unless this is an "undo" status change in which no new comment is expected
        if new_comment and not undo_status_change:
            suggestion.comment = new_comment

        suggestion.save()

        # Refresh activity_log
        suggestion_context.activity_log = self.fetch_activity_log(suggestion.pk)

        # Refresh packages edit status
        suggestion_context.package_list_context.editable = is_suggestion_editable(
            suggestion
        )

        if self._is_origin_url_a_list(request):
            if not undo_status_change:
                # If we come from a suggestion list, we don't update the component in
                # place because the list would mix suggestions of different statuses.
                # Instead, we show only a stub of the suggestion.
                #
                # However, if the status change is an "undo", then we want to show the
                # full suggestion again.
                suggestion_context.suggestion_stub_context = SuggestionStubContext(
                    suggestion,
                    issue_link=github_issue_link,
                    undo_status_target=undo_status_target,
                )
        else:
            # If we rerender but we are not in a suggestion list corresponding
            # to a specific status, we want to display the suggestion status so
            # the user can keep track
            suggestion_context.show_status = True

        if request.headers.get("HX-Request"):
            return self.render_to_response({"data": suggestion_context})
        else:
            return self._redirect_to_origin(request)


class PackageOperationBaseView(SuggestionBaseView, ABC):
    """Base view for package operations (ignore/restore) with common functionality."""

    # NOTE(@florentc): We replace the whole component because ultimately we
    # will want to also update the maintainers.
    # TODO: When we ignore a package, we'd like to automatically ignore its
    # maintainers
    template_name = "suggestions/components/suggestion.html"

    def post(
        self, request: HttpRequest, suggestion_id: int, package_attr: str
    ) -> HttpResponse:
        """Handle package operation requests."""
        if not request.user or not can_publish_github_issue(request.user):
            return HttpResponseForbidden()

        # Get suggestion context
        suggestion = self.fetch_suggestion(suggestion_id)
        suggestion_context = self.get_suggestion_context(suggestion)

        # Validate that the suggestion status allows package editing
        if suggestion.status not in [
            CVEDerivationClusterProposal.Status.PENDING,
            CVEDerivationClusterProposal.Status.ACCEPTED,
        ]:
            return self._handle_error(
                request,
                suggestion_context,
                "Package editing is not allowed for this suggestion status",
            )

        # Validate that the package exists in the suggestion
        if package_attr not in suggestion.cached.payload.get("original_packages", {}):
            return self._handle_error(
                request, suggestion_context, "Package not found in this suggestion"
            )

        # Perform the specific operation (to be implemented by subclasses)
        try:
            with transaction.atomic():
                self._perform_operation(suggestion, package_attr)
                new_active_packages = apply_package_edits(
                    suggestion.cached.payload["original_packages"],
                    suggestion.package_edits.all(),
                )
                suggestion.cached.payload["packages"] = new_active_packages
                suggestion.cached.save()
        except Exception:
            return self._handle_error(
                request,
                suggestion_context,
                f"Unable to {self._get_operation_name()} package",
            )

        # Refresh the package list context and activity log
        suggestion_context.package_list_context = get_package_list_context(suggestion)
        suggestion_context.activity_log = self.fetch_activity_log(suggestion.pk)

        # Handle response based on request type
        if request.headers.get("HX-Request"):
            # For HTMX requests, return the updated component
            return self.render_to_response({"data": suggestion_context})
        else:
            # For non-HTMX requests, redirect to origin
            return self._redirect_to_origin(request)

    @abstractmethod
    def _perform_operation(
        self, suggestion: CVEDerivationClusterProposal, package_attr: str
    ) -> None:
        """Perform the specific package operation. To be implemented by subclasses."""
        pass

    @abstractmethod
    def _get_operation_name(self) -> str:
        """Get the operation name for error messages. To be implemented by subclasses."""
        pass


class IgnorePackageView(PackageOperationBaseView):
    """Handle package ignore operations."""

    def _perform_operation(
        self, suggestion: CVEDerivationClusterProposal, package_attr: str
    ) -> None:
        """Create or update PackageEdit to ignore the package."""
        edit, created = suggestion.package_edits.get_or_create(
            package_attribute=package_attr,
            defaults={"edit_type": PackageEdit.EditType.REMOVE},
        )
        if not created and edit.edit_type != PackageEdit.EditType.REMOVE:
            edit.edit_type = PackageEdit.EditType.REMOVE
            edit.save()

    def _get_operation_name(self) -> str:
        return "ignore"


class RestorePackageView(PackageOperationBaseView):
    """Handle package restore operations."""

    def _perform_operation(
        self, suggestion: CVEDerivationClusterProposal, package_attr: str
    ) -> None:
        """Remove PackageEdit entries to restore the package."""
        suggestion.package_edits.filter(
            package_attribute=package_attr,
            edit_type=PackageEdit.EditType.REMOVE,
        ).delete()

    def _get_operation_name(self) -> str:
        return "restore"


class MaintainerOperationBaseView(SuggestionBaseView, ABC):
    template_name = "suggestions/components/suggestion.html"

    def post(
        self, request: HttpRequest, suggestion_id: int, github_id: str
    ) -> HttpResponse:
        """Handle maintainer operation requests."""
        if not request.user or not can_publish_github_issue(request.user):
            return HttpResponseForbidden()

        # Get suggestion context
        suggestion = self.fetch_suggestion(suggestion_id)
        suggestion_context = self.get_suggestion_context(suggestion)

        # Validate the github_id in input
        try:
            github_id_int = int(github_id)
        except ValueError:
            return self._handle_error(
                request, suggestion_context, "Invalid GitHub ID format"
            )

        # Validate that the suggestion status allows maintainer editing
        if suggestion.status not in [
            CVEDerivationClusterProposal.Status.PENDING,
            CVEDerivationClusterProposal.Status.ACCEPTED,
        ]:
            return self._handle_error(
                request,
                suggestion_context,
                "Maintainer editing is not allowed for this suggestion status",
            )

        # Validate the requested operation
        validation_error = self._validate_operation(suggestion, github_id_int)
        if validation_error:
            return self._handle_error(request, suggestion_context, validation_error)

        # Perform the specific operation
        try:
            self._perform_operation(suggestion, github_id_int)
        except Exception:
            return self._handle_error(
                request,
                suggestion_context,
                f"Unable to {self._get_operation_name()} maintainer",
            )

        # Refresh the maintainer list context and activity_log
        suggestion_context.maintainer_list_context = get_maintainer_list_context(
            suggestion
        )
        suggestion_context.activity_log = self.fetch_activity_log(suggestion.pk)

        # Return response
        if request.headers.get("HX-Request"):
            return self.render_to_response({"data": suggestion_context})
        else:
            return self._redirect_to_origin(request)

    @abstractmethod
    def _perform_operation(
        self, suggestion: CVEDerivationClusterProposal, github_id: int
    ) -> None:
        """Perform the specific maintainer operation. To be implemented by subclasses."""
        pass

    @abstractmethod
    def _validate_operation(
        self, suggestion: CVEDerivationClusterProposal, github_id: int
    ) -> str | None:
        """Validate if the operation can be performed. Return error message or None."""
        pass

    @abstractmethod
    def _get_operation_name(self) -> str:
        """Get the operation name for error messages. To be implemented by subclasses."""
        pass


class IgnoreMaintainerView(MaintainerOperationBaseView):
    """Ignore a maintainer that was automatically assigned to the suggestion."""

    def _validate_operation(
        self, suggestion: CVEDerivationClusterProposal, github_id: int
    ) -> str | None:
        """Validate that the maintainer can be ignored."""
        # Check if the maintainer exists in the original maintainers
        categorized_maintainers = suggestion.cached.payload["categorized_maintainers"]
        original_maintainers = categorized_maintainers["original"]

        # Find if this github_id exists in original maintainers
        maintainer_exists = any(
            maintainer.get("github_id") == github_id
            for maintainer in original_maintainers
        )

        if not maintainer_exists:
            return "Maintainer not found in original maintainers"

        # Check if already ignored (has a REMOVE edit)
        existing_edit = suggestion.maintainers_edits.filter(
            maintainer__github_id=github_id, edit_type=MaintainersEdit.EditType.REMOVE
        ).first()

        if existing_edit:
            return "Maintainer is already ignored"

        return None

    def _perform_operation(
        self, suggestion: CVEDerivationClusterProposal, github_id: int
    ) -> None:
        with transaction.atomic():
            # Get the maintainer object
            maintainer = NixMaintainer.objects.get(github_id=github_id)

            # Create the maintainer edit
            edit, created = suggestion.maintainers_edits.get_or_create(
                maintainer=maintainer,
                defaults={"edit_type": MaintainersEdit.EditType.REMOVE},
            )
            if not created and edit.edit_type != MaintainersEdit.EditType.REMOVE:
                edit.edit_type = MaintainersEdit.EditType.REMOVE
                edit.save()

            # Update the cached categorized maintainers
            categorized_maintainers = suggestion.cached.payload[
                "categorized_maintainers"
            ]
            categorized_maintainers["active"] = [
                m
                for m in categorized_maintainers["active"]
                if m["github_id"] != github_id
            ]
            categorized_maintainers["ignored"].append(to_dict(maintainer))

            # Save the suggestion
            suggestion.cached.save()

    def _get_operation_name(self) -> str:
        return "ignore"


class RestoreMaintainerView(MaintainerOperationBaseView):
    """Restore a maintainer that was previously ignored."""

    def _validate_operation(
        self, suggestion: CVEDerivationClusterProposal, github_id: int
    ) -> str | None:
        """Validate that the maintainer can be restored."""
        # Check if the maintainer exists in the ignored maintainers
        categorized_maintainers = suggestion.cached.payload["categorized_maintainers"]
        ignored_maintainers = categorized_maintainers["ignored"]

        # Find if this github_id exists in ignored maintainers
        maintainer_exists = any(
            maintainer.get("github_id") == github_id
            for maintainer in ignored_maintainers
        )

        if not maintainer_exists:
            return "Maintainer not found in ignored maintainers"

        # Check if there's a REMOVE edit to restore (there should be one)
        existing_edit = suggestion.maintainers_edits.filter(
            maintainer__github_id=github_id, edit_type=MaintainersEdit.EditType.REMOVE
        ).first()

        if not existing_edit:
            return "No ignore edit found for this maintainer"

        return None

    def _perform_operation(
        self, suggestion: CVEDerivationClusterProposal, github_id: int
    ) -> None:
        with transaction.atomic():
            # Remove the REMOVE edit to restore the maintainer
            edit_to_remove = suggestion.maintainers_edits.get(
                maintainer__github_id=github_id,
                edit_type=MaintainersEdit.EditType.REMOVE,
            )
            edit_to_remove.delete()
            maintainer = edit_to_remove.maintainer

            # Update the cached categorized maintainers
            categorized_maintainers = suggestion.cached.payload[
                "categorized_maintainers"
            ]
            categorized_maintainers["ignored"] = [
                m
                for m in categorized_maintainers["ignored"]
                if m["github_id"] != github_id
            ]
            categorized_maintainers["active"].append(to_dict(maintainer))

            # Save the suggestion
            suggestion.cached.save()

    def _get_operation_name(self) -> str:
        return "restore"


class AddMaintainerView(MaintainerOperationBaseView):
    """Manually add a maintainer that was not originally assigned to the suggestion."""

    def _perform_operation(
        self, suggestion: CVEDerivationClusterProposal, github_id: int
    ) -> None:
        pass

    def _get_operation_name(self) -> str:
        return "add"


class DeleteMaintainerView(MaintainerOperationBaseView):
    """Detele a maintainer that was manually added."""

    def _perform_operation(
        self, suggestion: CVEDerivationClusterProposal, github_id: int
    ) -> None:
        pass

    def _get_operation_name(self) -> str:
        return "delete"
