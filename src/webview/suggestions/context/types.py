from dataclasses import dataclass

from shared.logs.batches import FoldedEventType
from shared.models.linkage import CVEDerivationClusterProposal


@dataclass
class PackageListContext:
    active: dict
    ignored: dict
    editable: bool
    suggestion_id: int
    # TODO(@florentc): Add a state for whether to pre-open the "ignored
    # packages" list, in case it was already opened before component update


@dataclass
class SuggestionStubContext:
    suggestion: CVEDerivationClusterProposal
    issue_link: str | None
    undo_status_target: str | None  # FIXME(@florentc): change to the real enum type


@dataclass
class SuggestionContext:
    suggestion: CVEDerivationClusterProposal
    package_list_context: PackageListContext
    activity_log: list[FoldedEventType]
    show_status: bool = True
    suggestion_stub_context: SuggestionStubContext | None = None
    error_message: str | None = None
