from dataclasses import dataclass, field
from typing import Any

import pytest
from tuf.api.metadata import (
    TOP_LEVEL_ROLE_NAMES,
)

from tuf_conformance.client_runner import ClientRunner
from tuf_conformance.simulator_server import SimulatorServer

# DataSet is only here so type hints can be used.
DataSet = dict[str, Any]


@dataclass
class DelegationTester:
    delegator: str
    rolename: str
    keyids: list[str] = field(default_factory=list)
    threshold: int = 1
    terminating: bool = False
    paths: list[str] | None = field(default_factory=lambda: ["*"])
    path_hash_prefixes: list[str] | None = field(default_factory=list)


@dataclass
class TestTarget:
    rolename: str
    content: bytes
    targetpath: str


@dataclass
class SuccinctRolesTestCase:
    bit_length: int
    target_path: str
    expected_target_bin: str


@dataclass
class DelegationsTestCase:
    """A delegations graph as lists of delegations and target files
    and the expected order of traversal as a list of role names."""

    delegations: list[DelegationTester]
    target_files: list[TestTarget] = field(default_factory=list)
    visited_order: list[str] = field(default_factory=list)


succinct_bins_graph: DataSet = {
    "bin amount = 2, taget bin index 0": SuccinctRolesTestCase(
        bit_length=1,
        target_path="boo",
        expected_target_bin="bin-0",
    ),
    "bin amount = 2, taget bin index 1": SuccinctRolesTestCase(
        bit_length=1,
        target_path="too",
        expected_target_bin="bin-1",
    ),
    "bin amount = 4, taget bin index 0": SuccinctRolesTestCase(
        bit_length=2,
        target_path="foo",
        expected_target_bin="bin-0",
    ),
    "bin amount = 4, taget bin index 1": SuccinctRolesTestCase(
        bit_length=2,
        target_path="doo",
        expected_target_bin="bin-1",
    ),
    "bin amount = 4, taget bin index 2": SuccinctRolesTestCase(
        bit_length=2,
        target_path="too",
        expected_target_bin="bin-2",
    ),
    "bin amount = 4, taget bin index 3": SuccinctRolesTestCase(
        bit_length=2,
        target_path="bar",
        expected_target_bin="bin-3",
    ),
    "bin amount = 256, taget bin index fc": SuccinctRolesTestCase(
        bit_length=8,
        target_path="bar",
        expected_target_bin="bin-fc",
    ),
}


succinct_bins_graph_ids = succinct_bins_graph.keys()
succinct_bins_graph_cases = succinct_bins_graph.values()


@pytest.mark.parametrize(
    "succinct_bins_graph", succinct_bins_graph_cases, ids=succinct_bins_graph_ids
)
def test_succinct_roles_graph_traversal(
    client: ClientRunner,
    server: SimulatorServer,
    succinct_bins_graph: SuccinctRolesTestCase,
) -> None:
    """Test traversing the delegation tree when succinct roles is used. For a
    successful traversal all top level metadata files plus the expected
    bin should exist locally and only one bin must be downloaded."""
    exp_files = [*TOP_LEVEL_ROLE_NAMES, succinct_bins_graph.expected_target_bin]
    exp_calls = [(succinct_bins_graph.expected_target_bin, 1)]

    init_data, repo = server.new_test(client.test_name)
    repo.add_succinct_roles("targets", succinct_bins_graph.bit_length, "bin")
    repo.update_snapshot()
    assert client.init_client(init_data) == 0
    # Call explicitly refresh to simplify the expected_calls list.
    assert client.refresh(init_data) == 0
    repo.metadata_statistics.clear()
    # Check that metadata dir contains only top-level roles
    assert client._files_exist(TOP_LEVEL_ROLE_NAMES)

    # Looking for a non-existing targetpath forces updater
    # to visit a corresponding delegated role.
    client.download_target(init_data, succinct_bins_graph.target_path)
    # Here we could check that target_info is null. TODO: Add when
    # support for storing the target_info is added.

    # Check that the delegated roles were visited in the expected
    # order and the corresponding metadata files were persisted.
    assert repo.metadata_statistics[2:] == exp_calls
    assert client._files_exist(exp_files)
