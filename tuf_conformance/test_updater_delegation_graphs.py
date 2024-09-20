from dataclasses import astuple, dataclass, field

import pytest
from tuf.api.metadata import (
    DelegatedRole,
    Snapshot,
    Targets,
    Timestamp,
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
class TargetTestCase:
    targetpath: str
    found: bool
    visited_order: list[str] = field(default_factory=list)


@dataclass
class DelegationsTestCase:
    """A delegations graph as lists of delegations and target files
    and the expected order of traversal as a list of role names."""

    delegations: list[DelegationTester]
    target_files: list[TargetTest] = field(default_factory=list)
    visited_order: list[str] = field(default_factory=list)


# DataSet is only here so type hints can be used.
DataSet = dict[str, DelegationsTestCase]
DataSetTarget = dict[str, TargetTestCase]


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
    modified_roles = set()
    for d in test_case.delegations:
        if d.rolename in repo.mds:
            targets = repo.mds[d.rolename].signed
        else:
            targets = Targets(1, None, repo.safe_expiry, {}, None)

        # unpack 'd' but skip "delegator"
        role = DelegatedRole(*astuple(d)[1:])
        repo.add_delegation(d.delegator, role, targets)
        modified_roles.add(d.rolename)
        modified_roles.add(d.delegator)

    for target in test_case.target_files:
        repo.add_artifact(*astuple(target))

    repo.publish([*modified_roles, Snapshot.type, Timestamp.type])


@pytest.mark.parametrize("graphs", graph_cases, ids=graph_ids)
def test_graph_traversal(
    client: ClientRunner, server: SimulatorServer, graphs: DelegationsTestCase
) -> None:
    """Test that delegated roles are traversed in the order of appearance
    in the delegator's metadata, using pre-order depth-first search"""

    exp_calls = [(role, 1) for role in graphs.visited_order]

    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    init_repo(repo, graphs)

    assert client.download_target(init_data, "missingpath") == 1
    # skip the top level metadata (root, timestamp, snapshot, targets) in statistics
    assert repo.metadata_statistics[4:] == exp_calls


r"""
Create a single repository with the following delegations:

          targets
*.doc, *md / \ release/*/*
          A   B
 release/x/* / \ release/y/*.zip
            C   D

Test that Updater successfully finds the target files metadata,
traversing the delegations as expected.
"""
delegations_tree = DelegationsTestCase(
    delegations=[
        DelegationTester("targets", "A", paths=["*.doc", "*.md"]),
        DelegationTester("targets", "B", paths=["releases/*/*"]),
        DelegationTester("B", "C", paths=["releases/x/*"]),
        DelegationTester("B", "D", paths=["releases/y/*.zip"]),
    ],
    target_files=[
        TargetTest("targets", b"targetfile content", "targetfile"),
        TargetTest("A", b"README by A", "README.md"),
        TargetTest("C", b"x release by C", "releases/x/x_v1"),
        TargetTest("D", b"y release by D", "releases/y/y_v1.zip"),
        TargetTest("D", b"z release by D", "releases/z/z_v1.zip"),
    ],
)

targets: DataSetTarget = {
    "no delegations": TargetTestCase("targetfile", True, []),
    "targetpath matches wildcard": TargetTestCase("README.md", True, ["A"]),
    "targetpath with separators x": TargetTestCase("releases/x/x_v1", True, ["B", "C"]),
    "targetpath with separators y": TargetTestCase(
        "releases/y/y_v1.zip", True, ["B", "D"]
    ),
    "targetpath is not delegated by all roles in the chain": TargetTestCase(
        "releases/z/z_v1.zip", False, ["B"]
    ),
}


targets_ids = targets.keys()
targets_cases = targets.values()


@pytest.mark.parametrize("target", targets_cases, ids=targets_ids)
def test_targetfile_search(
    client: ClientRunner, server: SimulatorServer, target: TargetTestCase
) -> None:
    exp_calls = [(role, 1) for role in target.visited_order]

    init_data, repo = server.new_test(client.test_name)
    assert client.init_client(init_data) == 0
    init_repo(repo, delegations_tree)

    if target.found:
        assert client.download_target(init_data, target.targetpath) == 0
        assert client.get_downloaded_target_bytes() == [
            repo.artifacts[target.targetpath].data
        ]
    else:
        assert client.download_target(init_data, target.targetpath) == 1

    # skip the top level metadata (root, timestamp, snapshot, targets) in statistics
    assert repo.metadata_statistics[4:] == exp_calls
