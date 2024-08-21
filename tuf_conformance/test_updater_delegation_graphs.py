from dataclasses import astuple, dataclass, field

import pytest
from tuf.api.metadata import (
    SPECIFICATION_VERSION,
    DelegatedRole,
    Targets,
)

from tuf_conformance.client_runner import ClientRunner
from tuf_conformance.repository_simulator import RepositorySimulator
from tuf_conformance.simulator_server import SimulatorServer


@dataclass
class DelegationTester:
    delegator: str
    rolename: str
    keyids: list[str] | None = field(default_factory=list)
    threshold: int = 1
    terminating: bool = False
    paths: list[str] | None = field(default_factory=lambda: ["*"])


@dataclass
class TargetTest:
    rolename: str
    content: bytes
    targetpath: str


@dataclass
class DelegationsTestCase:
    """A delegations graph as lists of delegations and target files
    and the expected order of traversal as a list of role names."""

    delegations: list[DelegationTester]
    target_files: list[TargetTest] = field(default_factory=list)
    visited_order: list[str] = field(default_factory=list)


# DataSet is only here so type hints can be used.
DataSet = dict[str, DelegationsTestCase]


graphs: DataSet = {
    "basic-delegation": DelegationsTestCase(
        delegations=[DelegationTester("targets", "A")],
        visited_order=["A"],
    ),
    "single-level-delegations": DelegationsTestCase(
        delegations=[
            DelegationTester("targets", "A"),
            DelegationTester("targets", "B"),
        ],
        visited_order=["A", "B"],
    ),
    "two-level-delegations": DelegationsTestCase(
        delegations=[
            DelegationTester("targets", "A"),
            DelegationTester("targets", "B"),
            DelegationTester("B", "C"),
        ],
        visited_order=["A", "B", "C"],
    ),
    "two-level-test-DFS-order-of-traversal": DelegationsTestCase(
        delegations=[
            DelegationTester("targets", "A"),
            DelegationTester("targets", "B"),
            DelegationTester("A", "C"),
            DelegationTester("A", "D"),
        ],
        visited_order=["A", "C", "D", "B"],
    ),
    "three-level-delegation-test-DFS-order-of-traversal": DelegationsTestCase(
        delegations=[
            DelegationTester("targets", "A"),
            DelegationTester("targets", "B"),
            DelegationTester("A", "C"),
            DelegationTester("C", "D"),
        ],
        visited_order=["A", "C", "D", "B"],
    ),
    "two-level-terminating-ignores-all-but-roles-descendants": DelegationsTestCase(
        delegations=[
            DelegationTester("targets", "A"),
            DelegationTester("targets", "B"),
            DelegationTester("A", "C", terminating=True),
            DelegationTester("A", "D"),
        ],
        visited_order=["A", "C"],
    ),
    "three-level-terminating-ignores-all-but-roles-descendants": DelegationsTestCase(
        delegations=[
            DelegationTester("targets", "A"),
            DelegationTester("targets", "B"),
            DelegationTester("A", "C", terminating=True),
            DelegationTester("C", "D"),
        ],
        visited_order=["A", "C", "D"],
    ),
    "two-level-ignores-all-branches-not-matching-paths": DelegationsTestCase(
        delegations=[
            DelegationTester("targets", "A", paths=["*.py"]),
            DelegationTester("targets", "B"),
            DelegationTester("A", "C"),
        ],
        visited_order=["B"],
    ),
    "three-level-ignores-all-branches-not-matching-paths": DelegationsTestCase(
        delegations=[
            DelegationTester("targets", "A"),
            DelegationTester("targets", "B"),
            DelegationTester("A", "C", paths=["*.py"]),
            DelegationTester("C", "D"),
        ],
        visited_order=["A", "B"],
    ),
    "cyclic-graph": DelegationsTestCase(
        delegations=[
            DelegationTester("targets", "A"),
            DelegationTester("targets", "B"),
            DelegationTester("B", "C"),
            DelegationTester("C", "D"),
            DelegationTester("D", "B"),
        ],
        visited_order=["A", "B", "C", "D"],
    ),
    "two-roles-delegating-to-a-third": DelegationsTestCase(
        delegations=[
            DelegationTester("targets", "A"),
            DelegationTester("targets", "B"),
            DelegationTester("B", "C"),
            DelegationTester("A", "C"),
        ],
        # Under all same conditions, 'C' is reached through 'A' first"
        visited_order=["A", "C", "B"],
    ),
    "two-roles-delegating-to-a-third-different-paths": DelegationsTestCase(
        delegations=[
            DelegationTester("targets", "A"),
            DelegationTester("targets", "B"),
            DelegationTester("B", "C"),
            DelegationTester("A", "C", paths=["*.py"]),
        ],
        # 'C' is reached through 'B' since 'A' does not delegate a matching pattern"
        visited_order=["A", "B", "C"],
    ),
}


graph_ids = graphs.keys()
graph_cases = graphs.values()


def init_repo(repo: RepositorySimulator, test_case: DelegationsTestCase) -> None:
    spec_version = ".".join(SPECIFICATION_VERSION)
    for d in test_case.delegations:
        if d.rolename in repo.mds:
            targets = repo.mds[d.rolename].signed
        else:
            targets = Targets(1, spec_version, repo.safe_expiry, {}, None)
        # unpack 'd' but skip "delegator"
        role = DelegatedRole(*astuple(d)[1:])
        repo.add_delegation(d.delegator, role, targets)

    for target in test_case.target_files:
        repo.add_artifact(*astuple(target))

    repo.update_snapshot()


@pytest.mark.parametrize("graphs", graph_cases, ids=graph_ids)
def test_graph_traversal(
    client: ClientRunner, server: SimulatorServer, graphs: DelegationsTestCase
) -> None:
    """Test that delegated roles are traversed in the order of appearance
    in the delegator's metadata, using pre-order depth-first search"""

    if "clients/go-tuf/go-tuf" in client._cmd[0]:
        pytest.skip("skip for flakiness")

    exp_calls = [(role, 1) for role in graphs.visited_order]

    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    init_repo(repo, graphs)

    # Call explicitly refresh to simplify the expected_calls list
    assert client.refresh(init_data) == 0
    repo.metadata_statistics.clear()
    assert client.download_target(init_data, "missingpath") == 1
    # "('root', 2), ('timestamp', None)" gets prepended
    # in every case, so we compare from the 3rd item in the list.
    assert repo.metadata_statistics[2:] == exp_calls
