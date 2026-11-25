from dataclasses import dataclass

from pgpubsub.channel import Channel, TriggerChannel

from shared.models import NixDerivation
from shared.models.cve import Container
from shared.models.issue import NixpkgsIssue
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.nix_evaluation import NixChannel, NixEvaluation


@dataclass
class NixChannelUpdateChannel(TriggerChannel):
    model = NixChannel
    lock_notifications = True


@dataclass
class NixChannelInsertChannel(TriggerChannel):
    model = NixChannel
    lock_notifications = True


@dataclass
class NixEvaluationChannel(TriggerChannel):
    model = NixEvaluation
    # To avoid having a process blocked on the same evaluation multiple times.
    # We want to ensure that notifications are processed exactly once.
    # For this, we need to take a lock in the PostgreSQL database via `SELECT FOR UPDATE`
    # and let the pub-sub algorithm loop over available notifications with skip_locked.
    lock_notifications = True


@dataclass
class NixEvaluationUpdateChannel(TriggerChannel):
    model = NixEvaluation
    lock_notifications = True


@dataclass
class NixEvaluationSnapshotChannel(TriggerChannel):
    """
    Same events as `NixEvaluationUpdateChannel`, but its own notification and transaction,
    so a failure of clustering does not prevent the snapshot, and vice versa.
    """

    model = NixEvaluation
    lock_notifications = True


@dataclass
class NixDerivationChannel(TriggerChannel):
    model = NixDerivation


@dataclass
class ContainerChannel(TriggerChannel):
    model = Container
    # Process new structured data for a CVE only once.
    lock_notifications = True


@dataclass
class CVEDerivationClusterProposalChannel(TriggerChannel):
    model = CVEDerivationClusterProposal
    lock_notifications = True


@dataclass
class NixpkgsIssueChannel(TriggerChannel):
    model = NixpkgsIssue
    lock_notifications = False


@dataclass
class SuggestionRefreshChannel(Channel):
    pk: int
    lock_notifications = True


@dataclass
class CvePresentationChannel(Channel):
    """
    An update of the CVE record `pk` changed only what suggestions display (title, descriptions,
    references, metrics), not what matchers read: the cached payloads need rebuilding, nothing else.
    """

    pk: int
    lock_notifications = True


@dataclass
class SuggestionRematchChannel(Channel):
    """
    Re-match suggestion `pk` with every enabled matcher, because evaluation `evaluation_pk`
    added or changed attributes it matches or might match. Never re-emitted: not collected.
    """

    pk: int
    evaluation_pk: int
    lock_notifications = True


@dataclass
class PatchDetectionChannel(Channel):
    """
    Look for commits naming the CVE of exposures that evaluation `evaluation_pk` rebuilt on
    `branch` while affected (`exposure.detect_patches`): local git, so not in the step itself.
    """

    evaluation_pk: int
    branch: str
    lock_notifications = True


@dataclass
class BranchSnapshotChannel(Channel):
    """A branch's package snapshot advanced to `evaluation_pk`; its `BranchPackageChange` rows are written."""

    evaluation_pk: int
    branch: str
    lock_notifications = True


@dataclass
class CveUpdateChannel(Channel):
    """
    An update of the CVE record `pk` changed what matchers or the version classifier read.
    Presentation-only changes (title, descriptions, references, metrics) are not announced.
    """

    pk: int
    lock_notifications = True
