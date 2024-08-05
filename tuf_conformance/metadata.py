from tuf.api.metadata import (
    Metadata,
    Key,
)

import json

from securesystemslib.signer import Signature

from tuf.api._payload import (
    _ROOT,
    _SNAPSHOT,
    _TARGETS,
    _TIMESTAMP,
    Role,
    Root,
    Signed,
    Snapshot,
    T,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import (
    MetadataDeserializer,
)

from typing import Dict, Any, cast, List, Optional, Type


class MetadataTest(Metadata):
    @classmethod
    def from_dict(cls, metadata: Dict[str, Any]) -> "MetadataTest[T]":
        _type = metadata["signed"]["_type"]

        if _type == _TARGETS:
            inner_cls: Type[Signed] = Targets
        elif _type == _SNAPSHOT:
            inner_cls = Snapshot
        elif _type == _TIMESTAMP:
            inner_cls = Timestamp
        elif _type == _ROOT:
            inner_cls = RootTest
        else:
            raise ValueError(f'unrecognized metadata type "{_type}"')

        # Make sure signatures are unique
        signatures: Dict[str, Signature] = {}
        for sig_dict in metadata.pop("signatures"):
            sig = Signature.from_dict(sig_dict)
            signatures[sig.keyid] = sig

        return cls(
            # Specific type T is not known at static type check time: use cast
            signed=cast(T, inner_cls.from_dict(metadata.pop("signed"))),
            signatures=signatures,
            # All fields left in the metadata dict are unrecognized.
            unrecognized_fields=metadata,
        )


class RootTest(Root):
    def add_key(self, key: Key, role: str) -> None:
        # Adds a key even if it already exists
        if isinstance(role, Key):
            raise ValueError("Role must be a string, not a Key instance")

        if role not in self.roles:
            raise ValueError(f"Role {role} doesn't exist")
        self.roles[role].keyids.append(key.keyid)
        self.keys[key.keyid] = key

    @classmethod
    def from_dict(cls, signed_dict: Dict[str, Any]) -> "Root":
        """Create ``Root`` object from its json/dict representation.

        Raises:
            ValueError, KeyError, TypeError: Invalid arguments.
        """
        common_args = cls._common_fields_from_dict(signed_dict)
        consistent_snapshot = signed_dict.pop("consistent_snapshot", None)
        keys = signed_dict.pop("keys")
        roles = signed_dict.pop("roles")

        for keyid, key_dict in keys.items():
            keys[keyid] = Key.from_dict(keyid, key_dict)
        for role_name, role_dict in roles.items():
            roles[role_name] = RoleTest.from_dict(role_dict)

        # All fields left in the signed_dict are unrecognized.
        return cls(*common_args, keys, roles, consistent_snapshot, signed_dict)


class RoleTest(Role):
    # A copy of python-tufs Role class
    # without validation
    def __init__(
        self,
        keyids: List[str],
        threshold: int,
        unrecognized_fields: Optional[Dict[str, Any]] = None,
    ):
        self.keyids = keyids
        self.threshold = threshold
        if unrecognized_fields is None:
            unrecognized_fields = {}

        self.unrecognized_fields = unrecognized_fields


class JSONDeserializerTest(MetadataDeserializer):
    """Provides JSON to Metadata deserialize method."""

    def deserialize(self, raw_data: bytes) -> MetadataTest:
        """Deserialize utf-8 encoded JSON bytes into Metadata object."""
        json_dict = json.loads(raw_data.decode("utf-8"))
        metadata_obj = MetadataTest.from_dict(json_dict)
        """try:
            json_dict = json.loads(raw_data.decode("utf-8"))
            metadata_obj = MetadataTest.from_dict(json_dict)

        except Exception as e:
            raise DeserializationError("Failed to deserialize JSON") from e"""

        return metadata_obj
