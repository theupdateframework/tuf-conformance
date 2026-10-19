from datetime import UTC, datetime, timedelta

from tuf.api.metadata import DelegatedRole, Root, Snapshot, Targets, Timestamp

from tuf_conformance._internal import utils
from tuf_conformance._internal.client_runner import ClientRunner
from tuf_conformance._internal.simulator_server import SimulatorServer


def test_delegated_targets_expired(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """Ensures that the client does not use a delegated targets role that is
    already expired when the client first sees it.

    Spec 5.6.7 searches delegated roles and ends the search if a role cannot
    be validated; the freeze attack check (5.6, "the expiration timestamp in
    the new targets metadata file MUST be higher than the fixed update start
    time") applies to the delegated targets metadata. The expired role must be
    discarded and the artifact it describes must not be downloaded."""
    init_data, repo = server.new_test(client.test_name)
    assert client.init_client(init_data) == 0

    # Delegated role "delegated" is published already expired
    role = DelegatedRole("delegated", [], 1, False, ["delegatedpath/*"])
    delegated_targets = Targets(expires=utils.get_date_n_days_in_past(1))
    repo.add_delegation(Targets.type, role, delegated_targets)
    repo.add_artifact("delegated", b"delegated content", "delegatedpath/target")
    repo.publish(["delegated", Targets.type, Snapshot.type, Timestamp.type])

    # Top-level metadata is valid: refresh succeeds
    assert client.refresh(init_data) == 0

    # The only role that describes the artifact is expired: download must fail
    assert client.download_target(init_data, "delegatedpath/target") == 1
    assert client.get_downloaded_target_bytes() == []

    # Expired delegated metadata must not have been accepted as trusted
    assert client.trusted_roles() == [
        (Root.type, 1),
        (Snapshot.type, 2),
        (Targets.type, 2),
        (Timestamp.type, 2),
    ]


def test_expired_local_delegated_targets(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """Ensures that the client does not keep using a trusted delegated targets
    role after it has expired, when the repository has no newer version.

    The downloads and verifications are performed with the following timing:
     - Delegated role v1 expiry set to day 7
     - First download performed on day 0: delegated role becomes trusted
     - Second download (of another artifact in the same role) performed on
       day 18: the delegated role is expired and must not be used"""
    init_data, repo = server.new_test(client.test_name)
    assert client.init_client(init_data) == 0

    now = datetime.now(UTC)
    role = DelegatedRole("delegated", [], 1, False, ["delegatedpath/*"])
    repo.add_delegation(Targets.type, role, Targets(expires=now + timedelta(days=7)))
    repo.add_artifact("delegated", b"first", "delegatedpath/first")
    repo.add_artifact("delegated", b"second", "delegatedpath/second")
    repo.publish(["delegated", Targets.type, Snapshot.type, Timestamp.type])

    # Day 0: delegated role is valid, download succeeds
    assert client.download_target(init_data, "delegatedpath/first") == 0
    assert client.get_downloaded_target_bytes() == [b"first"]

    # Day 18: delegated role has expired and the repository still serves v1
    fake_time = now + timedelta(days=18)
    assert client.download_target(init_data, "delegatedpath/second", fake_time) == 1
    assert client.get_downloaded_target_bytes() == [b"first"]


def test_expired_local_delegated_targets_updates(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """Ensures that the client can update to a newer delegated targets role
    when the trusted local version has expired but the repository has a
    newer, unexpired version.

    The downloads and verifications are performed with the following timing:
     - Delegated role v1 expiry set to day 7
     - First download performed on day 0: delegated role v1 becomes trusted
     - Repository publishes delegated role v2 with expiry set to day 21
     - Second download performed on day 18 succeeds using v2"""
    init_data, repo = server.new_test(client.test_name)
    assert client.init_client(init_data) == 0

    now = datetime.now(UTC)
    role = DelegatedRole("delegated", [], 1, False, ["delegatedpath/*"])
    repo.add_delegation(Targets.type, role, Targets(expires=now + timedelta(days=7)))
    repo.add_artifact("delegated", b"first", "delegatedpath/first")
    repo.add_artifact("delegated", b"second", "delegatedpath/second")
    repo.publish(["delegated", Targets.type, Snapshot.type, Timestamp.type])

    # Day 0: delegated role v1 is valid, download succeeds
    assert client.download_target(init_data, "delegatedpath/first") == 0
    assert client.get_downloaded_target_bytes() == [b"first"]

    # Repository publishes delegated role v2 expiring on day 21
    repo.any_targets("delegated").expires = now + timedelta(days=21)
    repo.publish(["delegated", Snapshot.type, Timestamp.type])

    # Day 18: local v1 has expired but v2 from the repository has not
    fake_time = now + timedelta(days=18)
    assert client.download_target(init_data, "delegatedpath/second", fake_time) == 0
    assert client.get_downloaded_target_bytes() == [b"first", b"second"]
