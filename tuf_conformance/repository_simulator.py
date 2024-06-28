#!/usr/bin/env python

# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

""""Test utility to simulate a repository

RepositorySimulator provides methods to modify repository metadata so that it's
easy to "publish" new repository versions with modified metadata, while serving
the versions to client test code.

Metadata and targets "hosted" by the simulator are made available in URL paths
"/metadata/..." and "/targets/..." respectively.

Example::

    # constructor creates repository with top-level metadata
    sim = RepositorySimulator()

    # metadata can be modified directly: it is immediately available to clients
    sim.snapshot.version += 1

    # As an exception, new root versions require explicit publishing
    sim.root.version += 1
    sim.publish_root()

    # there are helper functions
    sim.add_target("targets", b"content", "targetpath")
    sim.targets.version += 1
    sim.update_snapshot()
"""

import datetime
import json
import logging
import os
import tempfile
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Tuple
from urllib import parse

import securesystemslib.hash as sslib_hash
from securesystemslib.signer import CryptoSigner, Signer

from tuf.api.metadata import (
    SPECIFICATION_VERSION,
    TOP_LEVEL_ROLE_NAMES,
    DelegatedRole,
    Delegations,
    Key,
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

logger = logging.getLogger(__name__)

SPEC_VER = ".".join(SPECIFICATION_VERSION)

@dataclass
class Artifact:
    """Contains actual artifact bytes and the related metadata."""
    data: bytes
    target_file: TargetFile


class RepositorySimulator():
    """Simulates a TUF repository that can be used for testing."""

    # pylint: disable=too-many-instance-attributes
    def __init__(self) -> None:
        self.md_delegates: Dict[str, Metadata[Targets]] = {}

        # other metadata is signed on-demand (when fetched) but roots must be
        # explicitly published with publish_root() which maintains this list
        self.signed_roots: List[bytes] = []

        # signers are used on-demand at fetch time to sign metadata
        # keys are roles, values are dicts of {keyid: signer}
        self.signers: Dict[str, Dict[str, Signer]] = {}

        # target downloads are served from this dict
        self.artifacts: Dict[str, Artifact] = {}

        # Whether to compute hashes and length for meta in snapshot/timestamp
        self.compute_metafile_hashes_length = False

        # Enable hash-prefixed target file names
        self.prefix_targets_with_hash = True

        self.dump_dir: Optional[str] = None
        self.dump_version = 0

        self.metadata_statistics: List[Tuple[str, Optional[int]]] = []
        self.artifact_statistics: List[Tuple[str, Optional[int]]] = []

        now = datetime.datetime.utcnow()
        self.safe_expiry = now.replace(microsecond=0) + datetime.timedelta(
            days=30
        )

        # initialize a basic repository structure
        self._initialize()

    @property
    def root(self) -> Root:
        return self.md_root.signed

    @property
    def timestamp(self) -> Timestamp:
        return self.md_timestamp.signed

    @property
    def snapshot(self) -> Snapshot:
        return self.md_snapshot.signed

    @property
    def targets(self) -> Targets:
        return self.md_targets.signed

    def all_targets(self) -> Iterator[Tuple[str, Targets]]:
        """Yield role name and signed portion of targets one by one."""
        parsed_targets = Metadata.from_bytes(self.md_targets_json)
        yield Targets.type, parsed_targets.signed
        #yield Targets.type, self.md_targets.signed
        # (ADAM) I have commented this out. Tests pass, but it might need to be reverted
        for role, md in self.md_delegates.items():
            yield role, md.signed

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
            signer = CryptoSigner.generate_ecdsa()
            self.root.add_key(signer.public_key, role)
            self.add_signer(role, signer)

    def _initialize(self) -> None:
        """Setup a minimal valid repository."""

        self.md_targets = Metadata(Targets(expires=self.safe_expiry))
        self.md_snapshot = Metadata(Snapshot(expires=self.safe_expiry))
        self.md_timestamp = Metadata(Timestamp(expires=self.safe_expiry))
        self.md_root = Metadata(Root(expires=self.safe_expiry))

        self.md_targets_json = Metadata(Targets(expires=self.safe_expiry)).to_bytes(JSONSerializer())
        self.md_snapshot_json = Metadata(Snapshot(expires=self.safe_expiry)).to_bytes(JSONSerializer())
        self.md_timestamp_json = Metadata(Timestamp(expires=self.safe_expiry)).to_bytes(JSONSerializer())
        self.md_root_json = Metadata(Root(expires=self.safe_expiry)).to_bytes(JSONSerializer())

        for role in TOP_LEVEL_ROLE_NAMES:
            signer = CryptoSigner.generate_ecdsa()

            # Update root in new way #
            root = Metadata.from_bytes(self.md_root_json)
            root.signed.add_key(signer.public_key, role)
            self.md_root_json = root.to_bytes(JSONSerializer())
            ##########################

            self.root.add_key(signer.public_key, role)
            self.add_signer(role, signer)

        self.publish_root()

    def set_root_consistent_snapshot(self, b: bool) -> None:
        root = Metadata.from_bytes(self.md_root_json)
        root.signed.consistent_snapshot = b
        self.md_root_json = root.to_bytes(JSONSerializer())
        self.root.consistent_snapshot = b

    def bump_root_by_one(self) -> None:
        self.bump_version_by_one(Root.type)
        self.publish_root()

    def bump_version_by_one(self, role: str) -> None:
        # Does not update hashes and signatures
        if role == Root.type:
            new_root = self.load_metadata(Root.type)
            new_root.signed.version += 1
            self.save_metadata(Root.type, new_root)
            #self.root.version += 1
        elif role == Snapshot.type:
            new_snapshot = self.load_metadata(Snapshot.type)
            new_snapshot.signed.version += 1
            self.save_metadata(Snapshot.type, new_snapshot)
            #self.snapshot.version += 1
        elif role == Timestamp.type:
            new_timestamp = self.load_metadata(Timestamp.type)
            new_timestamp.signed.version += 1
            self.save_metadata(Timestamp.type, new_timestamp)
            #self.timestamp.version += 1
        elif role == Targets.type:
            new_targets = self.load_metadata(Targets.type)
            new_targets.signed.version += 1
            self.save_metadata(Targets.type, new_targets)
            #self.targets.version += 1


    def add_key_to_role(self, role: str) -> None:
        """add new key"""
        signer = CryptoSigner.generate_ecdsa()

        # Update root in new way #
        root = Metadata.from_bytes(self.md_root_json)
        root.signed.add_key(signer.public_key, role)
        root.sign(signer, append=True)
        self.md_root_json = root.to_bytes(JSONSerializer())
        ##########################

        #self.root.add_key(signer.public_key, role)
        #self.md_root.sign(signer, append=True)

        self.add_signer(role, signer)

        if role == Timestamp.type:
            # Sign in old way
            #self.md_timestamp.sign(signer, append=True)
            ##################

            # Update Timestamp in new way #
            md = Metadata.from_bytes(self.md_timestamp_json)
            md.sign(signer, append=True)
            self.md_timestamp_json = md.to_bytes(JSONSerializer())
            ##########################

        elif role == Snapshot.type:
            self.md_snapshot.sign(signer, append=True)

            # Update Snapshot in new way #
            md = Metadata.from_bytes(self.md_snapshot_json)
            md.sign(signer, append=True)
            self.md_snapshot_json = md.to_bytes(JSONSerializer())
            ##########################

        elif role == Targets.type:
            #self.md_targets.sign(signer, append=True)       

            # Update Targets in new way #
            md = Metadata.from_bytes(self.md_targets_json)
            md.sign(signer, append=True)
            self.md_targets_json = md.to_bytes(JSONSerializer())
            ##########################

        print("self.md_snapshot", self.md_snapshot.signatures)

    def add_one_role_key_n_times_to_root(self, role: str, times: int) -> None:
        """add new key"""
        signer = CryptoSigner.generate_ecdsa()

        # Update in old way
        self.add_signer(role, signer)
        #self.root.add_key(signer.public_key, role)
        #self.md_root.sign(signer, append=True)

        # Update root in new way (old is above) #
        root = Metadata.from_bytes(self.md_root_json)
        root.signed.add_key(signer.public_key, role)
        root.sign(signer, append=True)
        self.md_root_json = root.to_bytes(JSONSerializer())
        existing_root = Metadata.from_bytes(self.md_root_json)
        ##########################

        if role == Timestamp.type:

            # Sign in new way #
            ts = Metadata.from_bytes(self.md_timestamp_json)
            ts.sign(signer, append=True)
            self.md_timestamp_json = ts.to_bytes(JSONSerializer())
            ##########################

            # old way
            #self.md_timestamp.sign(signer, append=True)
        elif role == Snapshot.type:

            # Sign in new way #
            ss = Metadata.from_bytes(self.md_snapshot_json)
            ss.sign(signer, append=True)
            self.md_snapshot_json = ss.to_bytes(JSONSerializer())
            ##########################

            # old way
            #self.md_snapshot.sign(signer, append=True)
        elif role == Targets.type:

            # Sign in new way #
            targ = Metadata.from_bytes(self.md_targets_json)
            targ.sign(signer, append=True)
            self.md_targets_json = targ.to_bytes(JSONSerializer())
            ##########################

            # old way
            #self.md_targets.sign(signer, append=True)
        
        # Add one key n times to root
        for n in range(0, times):
            # New # TODO: This needs to be done manually in the json,
            # because the deserializer checks for duplicates.
            #json_object = json.loads(self.md_root_json)
            #print("json:", json.dumps(json_object, indent=2))
            #existing_root = Metadata.from_bytes(self.md_root_json)
            #existing_root.signed.roles[role].keyids.append(signer.public_key.keyid)
            #self.md_root_json = existing_root.to_bytes(JSONSerializer())

            # Old
            self.root.roles[role].keyids.append(signer.public_key.keyid)

    def publish_root(self) -> None:
        """Sign and store a new serialized version of root."""

        # New
        existing_root = Metadata.from_bytes(self.md_root_json)
        existing_root.signatures.clear()
        self.md_root_json = existing_root.to_bytes(JSONSerializer())

        # Old
        self.md_root.signatures.clear()
        for signer in self.signers[Root.type].values():
            # New
            existing_root = Metadata.from_bytes(self.md_root_json)
            existing_root.sign(signer, append=True)
            self.md_root_json = existing_root.to_bytes(JSONSerializer())

            # Old
            self.md_root.sign(signer, append=True)

        # New
        self.signed_roots.append(self.md_root_json)

        # Old
        #self.signed_roots.append(self.md_root.to_bytes(JSONSerializer()))
        logger.debug("Published root v%d", self.root.version)

    def fetch_MitM(self, path: str) -> bytes:
        """Fetches and returns metadata/artifacts for the given url-path.

        Changes the datetime of metadatafiles

        This is called by the web server request handler.
        """
        _ = 2



    def fetch(self, path: str) -> bytes:
        """Fetches and returns metadata/artifacts for the given url-path.

        This is called by the web server request handler.
        """
        if path.startswith("metadata/") and path.endswith(".json"):
            # figure out rolename and version
            ver_and_name = path[len("metadata/") :][: -len(".json")]
            version_str, _, role = ver_and_name.partition(".")
            print("version_str, _, role:::::::::::::::: ", version_str, _, role)
            #print("version_str: ", version_str)
            # root is always version-prefixed while timestamp is always NOT
            uses_consistent_snapshot = self.load_metadata(Root.type).signed.consistent_snapshot

            if role == Root.type or (
                uses_consistent_snapshot and ver_and_name != Timestamp.type
            ):
                version: Optional[int] = int(version_str)
            else:
                # the file is not version-prefixed
                role = ver_and_name
                version = None
            print("role:::::::::::::::::2222", role, "version::::2222 ", version)

            return self.fetch_metadata(role, version)
        elif path.startswith("targets/"):
            # figure out target path and hash prefix
            target_path = path[len("targets/") :]
            dir_parts, sep, prefixed_filename = target_path.rpartition("/")
            # extract the hash prefix, if any
            prefix: Optional[str] = None
            filename = prefixed_filename
            uses_consistent_snapshot = self.load_metadata(Root.type).signed.consistent_snapshot
            if uses_consistent_snapshot and self.prefix_targets_with_hash:
                prefix, _, filename = prefixed_filename.partition(".")
            target_path = f"{dir_parts}{sep}{filename}"

            return self.fetch_target(target_path, prefix)
        raise ValueError(f"Unknown path '{path}'")

    def fetch_target(
        self, target_path: str, target_hash: Optional[str]
    ) -> bytes:
        """Return data for 'target_path', checking 'target_hash' if it is given.

        If hash is None, then consistent_snapshot is not used.
        """
        self.artifact_statistics.append((target_path, target_hash))

        repo_target = self.artifacts.get(target_path)
        if repo_target is None:
            print("NO TARGET")
            raise ValueError(f"No target {target_path}")
        if (
            target_hash
            and target_hash not in repo_target.target_file.hashes.values()
        ):
            raise ValueError(f"hash mismatch for {target_path}")

        logger.debug("fetched target %s", target_path)
        return repo_target.data

    def fetch_metadata(self, role: str, version: Optional[int] = None) -> bytes:
        print("version::::::::::::::::::::", version, "role    : ", role)
        """Return signed metadata for 'role', using 'version' if it is given.

        If version is None, non-versioned metadata is being requested.
        """
        self.metadata_statistics.append((role, version))
        # decode role for the metadata
        role = parse.unquote(role, encoding="utf-8")

        if role == Root.type:
            # return a version previously serialized in publish_root()
            if version is None or version > len(self.signed_roots):
                raise ValueError(f"Unknown root version {version}")
            logger.debug("fetched root version %d", version)
            return self.signed_roots[version - 1]

        # sign and serialize the requested metadata
        md: Optional[Metadata]
        if role == Timestamp.type:
            #md = self.md_timestamp
            md = Metadata.from_bytes(self.md_timestamp_json)
        elif role == Snapshot.type:
            #md = self.md_snapshot
            md = Metadata.from_bytes(self.md_snapshot_json)
        elif role == Targets.type:
            #md = self.md_targets
            md = Metadata.from_bytes(self.md_targets_json)
            #print("AAAAA: ", md2.signed.version)
        else:
            md = self.md_delegates.get(role)

        if md is None:
            raise ValueError(f"Unknown role {role}")

        md.signatures.clear()
        for signer in self.signers[role].values():
            print("Signing")
            md.sign(signer, append=True)
            #md2.sign(signer, append=True)

        logger.debug(
            "fetched %s v%d with %d sigs",
            role,
            md.signed.version,
            len(self.signers[role]),
        )
        return md.to_bytes(JSONSerializer())

    def _assert_version_equals(self, role: str, expected_version: int) -> None:
        """Assert that local metadata version is the expected"""
        if role == Snapshot.type:
            return Metadata.from_bytes(self.md_snapshot_json).signed.version == expected_version
        if role == Timestamp.type:
            return Metadata.from_bytes(self.md_timestamp_json).signed.version == expected_version

        #md = Metadata.from_file(os.path.join(self.metadata_dir, f"{role}.json"))
        #print("md:::::::::::::::::::", md.signed.version, "role:::::::::", role, "expected: ", expected_version)
        #return md.signed.version == expected_version

    def _compute_hashes_and_length(
        self, role: str
    ) -> Tuple[Dict[str, str], int]:
        data = self.fetch_metadata(role)
        digest_object = sslib_hash.digest(sslib_hash.DEFAULT_HASH_ALGORITHM)
        digest_object.update(data)
        hashes = {sslib_hash.DEFAULT_HASH_ALGORITHM: digest_object.hexdigest()}
        return hashes, len(data)

    def update_timestamp(self) -> None:
        """Update timestamp and assign snapshot version to snapshot_meta
        version.
        """

        hashes = None
        length = None
        if self.compute_metafile_hashes_length:
            hashes, length = self._compute_hashes_and_length(Snapshot.type)

        ############ new way: ##############
        existing_ss = Metadata.from_bytes(self.md_snapshot_json)
        new_ts = Metadata.from_bytes(self.md_timestamp_json)
        new_ts.signed.snapshot_meta = MetaFile(
            existing_ss.signed.version, length, hashes
        )
        new_ts.signed.version += 1
        self.md_timestamp_json = new_ts.to_bytes(JSONSerializer())
        ####################################

        # old way
        #self.timestamp.snapshot_meta = MetaFile(
        #    self.snapshot.version, length, hashes
        #)
        print("SAVED TIMESTAMP")

        #self.timestamp.version += 1

    def downgrade_timestamp(self) -> None:
        """Update timestamp and assign snapshot version to snapshot_meta
        version.
        """

        hashes = None
        length = None
        if self.compute_metafile_hashes_length:
            hashes, length = self._compute_hashes_and_length(Snapshot.type)

        ############ new way: ##############
        existing_ss = Metadata.from_bytes(self.md_snapshot_json)
        existing_ts = Metadata.from_bytes(self.md_timestamp_json)
        existing_ts.signed.snapshot_meta = MetaFile(
            existing_ss.signed.version, length, hashes
        )
        existing_ts.signed.version -= 1
        self.md_timestamp_json = existing_ts.to_bytes(JSONSerializer())
        ####################################

        self.timestamp.snapshot_meta = MetaFile(
            self.snapshot.version, length, hashes
        )

        #self.timestamp.version -= 1

    def update_snapshot(self) -> None:
        """Update snapshot, assign targets versions and update timestamp."""
        for role, delegate in self.all_targets():
            print("update_snapshot: role: ", role, "delegate: ", delegate)
            hashes = None
            length = None
            if self.compute_metafile_hashes_length:
                hashes, length = self._compute_hashes_and_length(role)

            ############ new way: ##############
            #new_ss = Metadata.from_bytes(self.md_snapshot_json)
            new_ss = self.load_metadata(Snapshot.type)
            new_ss.signed.meta[f"{role}.json"] = MetaFile(
                delegate.version, length, hashes
            )
            self.save_metadata(Snapshot.type, new_ss)
            #self.md_snapshot_json = existing_ss.to_bytes(JSONSerializer())
            ####################################

            #self.snapshot.meta[f"{role}.json"] = MetaFile(
            #    delegate.version, length, hashes
            #)

        ############ new way: ##############
        new_ss = self.load_metadata(Snapshot.type)
        new_ss.signed.version += 1
        self.save_metadata(Snapshot.type, new_ss)

        #existing_ss = Metadata.from_bytes(self.md_snapshot_json)
        #existing_ss.signed.version += 1
        #self.md_snapshot_json = existing_ss.to_bytes(JSONSerializer())
        ####################################

        print("S4444444444444VED SNAPSHOT. Now saving timestamp")

        #self.snapshot.version += 1
        self.update_timestamp()

    def downgrade_snapshot(self) -> None:
        """Update snapshot, assign targets versions and update timestamp.
           This is malicious behavior"""
        for role, delegate in self.all_targets():
            hashes = None
            length = None
            if self.compute_metafile_hashes_length:
                hashes, length = self._compute_hashes_and_length(role)

            ############ new way: ##############
            existing_ss = Metadata.from_bytes(self.md_snapshot_json)
            existing_ss.signed.meta[f"{role}.json"] = MetaFile(
                delegate.version, length, hashes
            )
            self.md_snapshot_json = existing_ss.to_bytes(JSONSerializer())
            ####################################

            self.snapshot.meta[f"{role}.json"] = MetaFile(
                delegate.version, length, hashes
            )

        ############ new way: ##############
        existing_ss = Metadata.from_bytes(self.md_snapshot_json)
        existing_ss.signed.version -= 1
        self.md_snapshot_json = existing_ss.to_bytes(JSONSerializer())
        ####################################

        #self.snapshot.version -= 1
        self.update_timestamp()

    def _get_delegator(self, delegator_name: str) -> Targets:
        """Given a delegator name return, its corresponding Targets object."""
        if delegator_name in TOP_LEVEL_ROLE_NAMES:
            return self.load_metadata(delegator_name)

        '''if delegator_name == Targets.type || :
            return Metadata.from_bytes(self.md_targets_json)
            #return self.targets
        if delegator_name == Targets.type:
            return Metadata.from_bytes(self.md_targets_json)
            #return self.targets
        if delegator_name == Targets.type:
            return Metadata.from_bytes(self.md_targets_json)
            #return self.targets
        if delegator_name == Targets.type:
            return Metadata.from_bytes(self.md_targets_json)'''
            #return self.targets


        return self.md_delegates[delegator_name]

    def add_target(self, role: str, data: bytes, path: str) -> None:
        """Create a target from data and add it to the target_files."""
        targets = self._get_delegator(role)

        target = TargetFile.from_data(path, data, ["sha256"])
        targets.targets[path] = target
        self.artifacts[path] = Artifact(data, target)
        print(targets.to_dict())

    def add_target_with_length(self, role: str, data: bytes, path: str, length: int) -> None:
        """Create a target from data and add it to the target_files.
           The hash value can be invalid compared to the length"""
        targets = self._get_delegator(role)
        print("DELEGATORRRRRRRRRRRRR: ", targets)

        target = TargetFile.from_data(path, data, ["sha256"])
        target.length = length
        targets.signed.targets[path] = target
        self.md_targets_json = targets.to_bytes(JSONSerializer())
        self.artifacts[path] = Artifact(data, target)
        print("TARGETSSSSS: ", targets.signed.to_dict())

    def add_delegation(
        self, delegator_name: str, role: DelegatedRole, targets: Targets
    ) -> None:
        """Add delegated target role to the repository."""
        delegator = self._get_delegator(delegator_name)

        if (
            delegator.signed.delegations is not None
            and delegator.signed.delegations.succinct_roles is not None
        ):
            raise ValueError("Can't add a role when succinct_roles is used")

        # Create delegation
        if delegator.signed.delegations is None:
            delegator.signed.delegations = Delegations({}, roles={})

        assert delegator.signed.delegations.roles is not None
        # put delegation last by default
        delegator.signed.delegations.roles[role.name] = role

        # By default add one new key for the role
        signer = CryptoSigner.generate_ecdsa()
        delegator.signed.add_key(signer.public_key, role.name)
        self.add_signer(role.name, signer)

        # New way: Save delegator
        if role == Targets.type:
            self.md_targets_json = delegator.to_bytes(JSONSerializer())
        elif role == Snapshot.type:
            self.md_snapshot_json = delegator.to_bytes(JSONSerializer())
        elif role == Root.type:
            self.md_root_json = delegator.to_bytes(JSONSerializer())
        elif role == Timestamp.type:
            self.md_timestamp_json = delegator.to_bytes(JSONSerializer())


        # Add metadata for the role
        if role.name not in self.md_delegates:
            print("adding delegate ---------------------- ", role)
            self.md_delegates[role.name] = Metadata(targets, {})

    def load_metadata(self, role: str) -> None:
        # Returns a parsed copy of the repositorys metadata
        if role == Targets.type:
            return Metadata.from_bytes(self.md_targets_json)
        elif role == Snapshot.type:
            return Metadata.from_bytes(self.md_snapshot_json)
        elif role == Root.type:
            return Metadata.from_bytes(self.md_root_json)
        elif role == Timestamp.type:
            return Metadata.from_bytes(self.md_timestamp_json)

    def save_metadata(self, role: str, md: Metadata) -> None:
        if role == Targets.type:
            self.md_targets_json = md.to_bytes(JSONSerializer())
        elif role == Snapshot.type:
            self.md_snapshot_json = md.to_bytes(JSONSerializer())
        elif role == Root.type:
            self.md_root_json = md.to_bytes(JSONSerializer())
        elif role == Timestamp.type:
            self.md_timestamp_json = md.to_bytes(JSONSerializer())

    def add_succinct_roles(
        self, delegator_name: str, bit_length: int, name_prefix: str
    ) -> None:
        """Add succinct roles info to a delegator with name "delegator_name".

        Note that for each delegated role represented by succinct roles an empty
        Targets instance is created.
        """
        delegator = self._get_delegator(delegator_name)

        if (
            delegator.delegations is not None
            and delegator.delegations.roles is not None
        ):
            raise ValueError(
                "Can't add a succinct_roles when delegated roles are used"
            )

        signer = CryptoSigner.generate_ecdsa()
        succinct_roles = SuccinctRoles([], 1, bit_length, name_prefix)
        delegator.delegations = Delegations({}, None, succinct_roles)

        # Add targets metadata for all bins.
        for delegated_name in succinct_roles.get_roles():
            self.md_delegates[delegated_name] = Metadata(
                Targets(expires=self.safe_expiry)
            )

            self.add_signer(delegated_name, signer)

        delegator.add_key(signer.public_key)

    def write(self) -> None:
        """Dump current repository metadata to self.dump_dir

        This is a debugging tool: dumping repository state before running
        Updater refresh may be useful while debugging a test.
        """
        if self.dump_dir is None:
            self.dump_dir = tempfile.mkdtemp()
            print(f"Repository Simulator dumps in {self.dump_dir}")

        self.dump_version += 1
        dest_dir = os.path.join(self.dump_dir, str(self.dump_version))
        os.makedirs(dest_dir)

        for ver in range(1, len(self.signed_roots) + 1):
            with open(os.path.join(dest_dir, f"{ver}.root.json"), "wb") as f:
                f.write(self.fetch_metadata(Root.type, ver))

        for role in [Timestamp.type, Snapshot.type, Targets.type]:
            with open(os.path.join(dest_dir, f"{role}.json"), "wb") as f:
                f.write(self.fetch_metadata(role))

        for role in self.md_delegates:
            quoted_role = parse.quote(role, "")
            with open(os.path.join(dest_dir, f"{quoted_role}.json"), "wb") as f:
                f.write(self.fetch_metadata(role))
