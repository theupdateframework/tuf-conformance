#!/usr/bin/env python

# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

""" "Test utility to simulate a repository

RepositorySimulator provides methods to modify repository metadata so that it's
easy to "publish" new repository versions with modified metadata, while serving
the versions to client test code.

Metadata and targets "hosted" by the simulator are made available in URL paths
"/metadata/..." and "/targets/..." respectively.

Example::

    # constructor creates repository with top-level metadata
    sim = RepositorySimulator()

    # publish a new version of metadata
    sim.root.expires = datetime.datetime.utcnow() + datetime.timedelta(days=7)
    sim.publish([Root.type])

    # there are helper functions to do things like adding an artifact
    sim.add_target(Targets.type, b"content", "targetpath")
    sim.publish([Targets.type, Snapshot.type, Timestamp.type])
"""

import datetime
import logging
import os
from collections.abc import Iterable
from dataclasses import dataclass
from urllib import parse

import securesystemslib.hash as sslib_hash
from securesystemslib.signer import CryptoSigner, Signer
from tuf.api.metadata import (
    SPECIFICATION_VERSION,
    TOP_LEVEL_ROLE_NAMES,
    DelegatedRole,
    Delegations,
    Metadata,
    MetaFile,
    Root,
    Snapshot,
    SuccinctRoles,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer

from tuf_conformance.metadata import MetadataTest, RootTest

logger = logging.getLogger(__name__)

SPEC_VER = ".".join(SPECIFICATION_VERSION)

# Generate some signers once (to avoid all tests generating them)
NUM_SIGNERS = 9
SIGNERS = {
    ("rsa", "rsassa-pss-sha256"): [
        CryptoSigner.generate_rsa() for _ in range(NUM_SIGNERS)
    ],
    ("rsa", "rsa-pkcs1v15-sha256"): [
        CryptoSigner.generate_rsa(scheme="rsa-pkcs1v15-sha256")
        for _ in range(NUM_SIGNERS)
    ],
    ("ecdsa", "ecdsa-sha2-nistp256"): [
        CryptoSigner.generate_ecdsa() for _ in range(NUM_SIGNERS)
    ],
    ("ed25519", "ed25519"): [
        CryptoSigner.generate_ed25519() for _ in range(NUM_SIGNERS)
    ],
}


@dataclass
class Artifact:
    """Contains actual artifact bytes and the related metadata."""

    data: bytes
    target_file: TargetFile


class RepositorySimulator:
    """Simulates a TUF repository that can be used for testing."""

    # pylint: disable=too-many-instance-attributes
    def __init__(self, dump_dir: str | None) -> None:
        # All current metadata
        self.mds: dict[str, Metadata] = {}

        # All signed metadata
        self.signed_mds: dict[str, list[bytes]] = {}

        # signers are used to sign metadata
        # keys are roles, values are dicts of {keyid: signer}
        self.signers: dict[str, dict[str, Signer]] = {}

        # target downloads are served from this dict
        self.artifacts: dict[str, Artifact] = {}

        # Whether to compute hashes and length for meta in snapshot/timestamp
        self.compute_metafile_hashes_length = False

        # Enable hash-prefixed target file names
        self.prefix_targets_with_hash = True

        self.dump_dir = dump_dir
        self.dump_version = 0

        self.metadata_statistics: list[tuple[str, int | None]] = []
        self.artifact_statistics: list[tuple[str, str | None]] = []

        now = datetime.datetime.utcnow()
        self.safe_expiry = now.replace(microsecond=0) + datetime.timedelta(days=30)

        # Make a semi-deep copy of generated signers
        self._generated_signers = {k: v.copy() for k, v in SIGNERS.items()}

        # initialize a basic repository structure
        self._initialize()

    @property
    def root(self) -> Root:
        signed = self.mds[Root.type].signed
        assert isinstance(signed, Root)
        return signed

    @property
    def timestamp(self) -> Timestamp:
        signed = self.mds[Timestamp.type].signed
        assert isinstance(signed, Timestamp)
        return signed

    @property
    def snapshot(self) -> Snapshot:
        signed = self.mds[Snapshot.type].signed
        assert isinstance(signed, Snapshot)
        return signed

    @property
    def targets(self) -> Targets:
        return self.any_targets("targets")

    def any_targets(self, role: str) -> Targets:
        signed = self.mds[role].signed
        assert isinstance(signed, Targets)
        return signed

    def new_signer(
        self, keytype: str = "rsa", scheme: str = "rsa-pkcs1v15-sha256"
    ) -> CryptoSigner:
        """Return a Signer (from a set of pre-generated signers)."""
        try:
            return self._generated_signers[(keytype, scheme)].pop()
        except KeyError:
            raise ValueError(f"Unsupported keytype/scheme: {keytype}/{scheme}")
        except IndexError:
            raise RuntimeError(
                f"Test ran out of {keytype}/{scheme} keys (NUM_SIGNERS = {NUM_SIGNERS})"
            )

    def add_signer(self, role: str, signer: CryptoSigner) -> None:
        if role not in self.signers:
            self.signers[role] = {}
        keyid = signer.public_key.keyid
        self.signers[role][keyid] = signer

    def rotate_keys(self, role: str) -> None:
        """remove all keys for role, then add threshold of new keys"""
        self.root.roles[role].keyids.clear()
        self.signers[role].clear()
        for _ in range(0, self.root.roles[role].threshold):
            signer = self.new_signer()
            self.root.add_key(signer.public_key, role)
            self.add_signer(role, signer)

    def _initialize(self) -> None:
        """Setup a minimal valid repository."""

        self.mds[Targets.type] = MetadataTest(Targets(expires=self.safe_expiry))
        self.mds[Snapshot.type] = MetadataTest(Snapshot(expires=self.safe_expiry))
        self.mds[Timestamp.type] = MetadataTest(Timestamp(expires=self.safe_expiry))
        self.mds[Root.type] = MetadataTest(RootTest(expires=self.safe_expiry))

        for role in TOP_LEVEL_ROLE_NAMES:
            signer = self.new_signer()
            self.root.add_key(signer.public_key, role)
            self.add_signer(role, signer)

        self.publish([Targets.type, Snapshot.type, Timestamp.type, Root.type])

    def publish(self, roles: Iterable[str], verify_version: bool = True) -> None:
        """Makes the repositorys metadata public and available to clients.

        Tests run this helper after updating the repositorys metadata
        and before clients should fetch the repositorys updated metadata.

        publish bumps the version by default. The role must already exist
        in repo.signed_mds for the repo to be able to bump it.

        When publishing a role that is not root, timestamp or snapshot,
        publish will create a metafile for the role and add it to snapshot.

        When publishing snapshot, publish will create a metafile for snapshot
        and add it to timestamp."""

        for role in roles:
            md = self.mds.get(role)
            if md is None:
                raise ValueError(f"Unknown role {role}")

            # only bump if there is a version already (this avoids bumping initial v1)
            if role in self.signed_mds:
                md.signed.version += 1

            md.signatures.clear()
            for signer in self.signers[role].values():
                md.sign(signer, append=True)

            logger.debug(
                "signed %s v%d with %d sigs",
                role,
                md.signed.version,
                len(self.signers[role]),
            )

            if role not in self.signed_mds:
                self.signed_mds[role] = []
            expected_ver = len(self.signed_mds[role]) + 1
            if verify_version and md.signed.version != expected_ver:
                raise ValueError(
                    f"RepositorySimulator Expected {role} v{expected_ver}, got "
                    "v{md.signed.version}. Use verify_version=False if this is intended"
                )

            self.signed_mds[role].append(md.to_bytes(JSONSerializer()))

            hashes = None
            length = None
            if self.compute_metafile_hashes_length:
                hashes, length = self._compute_hashes_and_length(role)

            # for targets roles: update snapshot.meta
            if role not in [Root.type, Timestamp.type, Snapshot.type]:
                self.snapshot.meta[f"{role}.json"] = MetaFile(
                    md.signed.version, length, hashes
                )
            # for snapshot: update timestamp.snapshot_meta
            if role == Snapshot.type:
                self.timestamp.snapshot_meta = MetaFile(
                    md.signed.version, length, hashes
                )

    def fetch(self, path: str) -> bytes:
        """Fetches and returns metadata/artifacts for the given url-path.

        This is called by the web server request handler.
        """
        if path.startswith("metadata/") and path.endswith(".json"):
            # figure out rolename and version
            ver_and_name = path[len("metadata/") :][: -len(".json")]
            version_str, _, role = ver_and_name.partition(".")
            # root is always version-prefixed while timestamp is always NOT
            if role == Root.type or (
                self.root.consistent_snapshot and ver_and_name != Timestamp.type
            ):
                version: int | None = int(version_str)
            else:
                # the file is not version-prefixed
                role = ver_and_name
                version = None

            self.metadata_statistics.append((role, version))
            return self.fetch_metadata(role, version)
        elif path.startswith("targets/"):
            # figure out target path and hash prefix
            target_path = path[len("targets/") :]
            dir_parts, sep, prefixed_filename = target_path.rpartition("/")
            # extract the hash prefix, if any
            prefix: str | None = None
            filename = prefixed_filename
            if self.root.consistent_snapshot and self.prefix_targets_with_hash:
                prefix, _, filename = prefixed_filename.partition(".")
            target_path = f"{dir_parts}{sep}{filename}"

            self.artifact_statistics.append((target_path, prefix))
            return self.fetch_target(target_path, prefix)
        raise ValueError(f"Unknown path '{path}'")

    def fetch_target(self, target_path: str, target_hash: str | None) -> bytes:
        """Return data for 'target_path' if it is given.

        If hash is None, then consistent_snapshot is not used.
        """
        repo_target = self.artifacts.get(target_path)
        if repo_target is None:
            raise ValueError(f"No target {target_path}")
        if target_hash and target_hash not in repo_target.target_file.hashes.values():
            raise ValueError(f"hash mismatch for {target_path}")

        logger.debug("fetched target %s", target_path)
        return repo_target.data

    def fetch_metadata(self, role: str, version: int | None = None) -> bytes:
        """Return signed metadata for 'role', using 'version' if it is given.

        If version is None, non-versioned metadata is being requested, and the
        repository will return the metadata it has published last.

        fetch_metadata versions its metadata by storing the version in
        repo.signed_mds[role][version-1].

        For the metadata to be available to the client, it must exist in
        repo.signed_mds. repo.publish() is responsible for makeing the
        metadata available in repo.signed_mds. The common workflow for
        making changes in a test and fetching is:
        1. Make changes to the metadata in the test
        2. Publish the metadata by way of repo.publish([role])
        3. The client can now fetch the updated metadata.
        """

        # decode role for the metadata
        role = parse.unquote(role, encoding="utf-8")

        if role == Root.type:
            if version is None or version > len(self.signed_mds[Root.type]):
                raise ValueError(f"Unknown root version {version}")
            return self.signed_mds[Root.type][version - 1]
        # Non-root mds:
        if len(self.signed_mds[role]) == 0:
            raise ValueError(f"The repository has not published metadata for '{role}'")
        if version is not None:
            return self.signed_mds[role][version - 1]
        return self.signed_mds[role][-1]

    def _version(self, role: str) -> int:
        signed = self.mds[role].signed
        assert isinstance(signed, Root | Timestamp | Snapshot | Targets)
        return signed.version

    def _compute_hashes_and_length(self, role: str) -> tuple[dict[str, str], int]:
        data = self.signed_mds[role][-1]
        digest_object = sslib_hash.digest(sslib_hash.DEFAULT_HASH_ALGORITHM)
        digest_object.update(data)
        hashes = {sslib_hash.DEFAULT_HASH_ALGORITHM: digest_object.hexdigest()}
        return hashes, len(data)

    def add_artifact(self, role: str, data: bytes, path: str) -> None:
        """Add `data` to artifact store and insert its hashes into metadata."""
        targets = self.any_targets(role)

        target = TargetFile.from_data(path, data, ["sha256"])
        targets.targets[path] = target
        self.artifacts[path] = Artifact(data, target)

    def add_delegation(
        self, delegator_name: str, role: DelegatedRole, targets: Targets
    ) -> None:
        """Add delegated targets role to the repository."""
        delegator = self.any_targets(delegator_name)

        if (
            delegator.delegations is not None
            and delegator.delegations.succinct_roles is not None
        ):
            raise ValueError("Can't add a role when succinct_roles is used")

        # Create delegation
        if delegator.delegations is None:
            delegator.delegations = Delegations({}, roles={})

        assert delegator.delegations.roles is not None
        # put delegation last by default
        delegator.delegations.roles[role.name] = role

        # By default add one new key for the role
        signer = self.new_signer()
        delegator.add_key(signer.public_key, role.name)
        self.add_signer(role.name, signer)

        # Add metadata for the role
        if role.name not in self.mds:
            self.mds[role.name] = Metadata(targets, {})

    def add_succinct_roles(
        self, delegator_name: str, bit_length: int, name_prefix: str
    ) -> None:
        """Add succinct roles info to a delegator with
        name "delegator_name".

        Note that for each delegated role represented
        by succinct roles an empty Targets instance
        is created.
        """
        delegator = self.any_targets(delegator_name)

        if (
            delegator.delegations is not None
            and delegator.delegations.roles is not None
        ):
            raise ValueError("Can't add a succinct_roles when delegated roles are used")

        signer = self.new_signer()
        succinct_roles = SuccinctRoles([], 1, bit_length, name_prefix)
        delegator.delegations = Delegations({}, None, succinct_roles)

        # Add targets metadata for all bins.
        for delegated_name in succinct_roles.get_roles():
            self.mds[delegated_name] = Metadata(Targets(expires=self.safe_expiry))

            self.add_signer(delegated_name, signer)

        delegator.add_key(signer.public_key)

    def debug_dump(self) -> None:
        """Dump current repository metadata to self.dump_dir

        This is a debugging tool: dumping repository state before running
        Updater refresh may be useful while debugging a test.

        If dump_dir is None, dumping does not happen
        """
        if not self.dump_dir:
            return

        self.dump_version += 1
        dest_dir = os.path.join(self.dump_dir, f"refresh-{self.dump_version}")
        os.makedirs(dest_dir, exist_ok=True)

        for ver in range(1, len(self.signed_mds[Root.type]) + 1):
            with open(os.path.join(dest_dir, f"{ver}.root.json"), "wb") as f:
                f.write(self.fetch_metadata(Root.type, ver))

        for role in self.signed_mds:
            if role == Root.type:
                continue
            quoted_role = parse.quote(role, "")
            with open(os.path.join(dest_dir, f"{quoted_role}.json"), "wb") as f:
                f.write(self.fetch_metadata(role))

    def add_key(
        self,
        role: str,
        delegator_name: str = Root.type,
        signer: CryptoSigner | None = None,
    ) -> None:
        """add new public key to delegating metadata and store the signer for role"""
        if signer is None:
            signer = self.new_signer()

        # Add key to delegating metadata
        delegator = self.mds[delegator_name].signed
        assert isinstance(delegator, Root | Targets)
        delegator.add_key(signer.public_key, role)

        # Add signer to signers
        self.add_signer(role, signer)
