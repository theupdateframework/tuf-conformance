from typing import List, Optional, Dict, Any

from tuf.api.metadata import (
    SPECIFICATION_VERSION,
    TOP_LEVEL_ROLE_NAMES,
    DelegatedRole,
    Targets,
)

from dataclasses import dataclass, field, astuple
import pytest
from tuf_conformance.client_runner import ClientRunner
from tuf_conformance.simulator_server import SimulatorServer
from tuf_conformance.repository_simulator import RepositorySimulator

# DataSet is only here so type hints can be used.
DataSet = Dict[str, Any]


@dataclass
class DelegationTester:
    delegator: str
    rolename: str
    keyids: List[str] = field(default_factory=list)
    threshold: int = 1
    terminating: bool = False
    paths: Optional[List[str]] = field(default_factory=lambda: ["*"])
    path_hash_prefixes: Optional[List[str]] = None


@dataclass
class TestTarget:
    rolename: str
    content: bytes
    targetpath: str


@dataclass
class DelegationsTestCase:
    """A delegations graph as lists of delegations and target files
    and the expected order of traversal as a list of role names."""

    delegations: List[DelegationTester]
    target_files: List[TestTarget] = field(default_factory=list)
    visited_order: List[str] = field(default_factory=list)


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
        if d.rolename in repo.md_delegates:
            targets = repo.md_delegates[d.rolename].signed
        else:
            targets = Targets(1, spec_version, repo.safe_expiry, {}, None)
        # unpack 'd' but skip "delegator"
        role = DelegatedRole(*astuple(d)[1:])
        repo.add_delegation(d.delegator, role, targets)

    for target in test_case.target_files:
        repo.add_target(*astuple(target))

    if test_case.target_files:
        repo.targets.version += 1
    repo.update_snapshot()


@pytest.mark.parametrize("graphs", graph_cases, ids=graph_ids)
def test_graph_traversal(
    client: ClientRunner, server: SimulatorServer, graphs: DelegationsTestCase
) -> None:
    """Test that delegated roles are traversed in the order of appearance
    in the delegator's metadata, using pre-order depth-first search"""
    exp_files = [*TOP_LEVEL_ROLE_NAMES, *graphs.visited_order]
    exp_calls = [(role, 1) for role in graphs.visited_order]

    init_data, repo = server.new_test(client.test_name)
    assert client.init_client(init_data) == 0
    init_repo(repo, graphs)

    # Call explicitly refresh to simplify the expected_calls list
    client.refresh(init_data)
    repo.metadata_statistics.clear()
    assert client._files_exist(TOP_LEVEL_ROLE_NAMES)
    client.download_target(init_data, "missingpath")
    # For some reason "('root', 2), ('timestamp', None)" gets prepended
    # in every case, so we compare from the 3rd item in the list.
    assert repo.metadata_statistics[2:] == exp_calls
    assert client._files_exist(exp_files)
