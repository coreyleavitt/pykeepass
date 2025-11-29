"""
KDBX database structure builder for KDBX3 and KDBX4 formats.

This module provides functions and configuration dataclasses for building
new KeePass database structures from scratch.
"""

from __future__ import annotations

import base64
import os
import struct
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from construct import Container, ListContainer
from lxml import etree
from lxml.builder import E

from .kdbx4 import kdf_uuids

# -------------------- Constants --------------------

# KDBX file signatures
KDBX_SIG1 = b'\x03\xd9\xa2\x9a'
KDBX_SIG2 = b'\x67\xfb\x4b\xb5'

# KDBX version numbers
KDBX3_MAJOR_VERSION = 3
KDBX3_MINOR_VERSION = 1
KDBX4_MAJOR_VERSION = 4
KDBX4_MINOR_VERSION = 0

# IV sizes per cipher
IV_SIZES = {
    'aes256': 16,
    'chacha20': 12,
    'twofish': 16,
}

# VariantDictionary type flags (KDBX4)
VD_UINT32 = 0x04
VD_UINT64 = 0x05
VD_BYTES = 0x42

# Argon2 version constant
ARGON2_VERSION = 0x13  # Version 19

# XML defaults
DEFAULT_DATABASE_NAME = "Database"
DEFAULT_HISTORY_MAX_ITEMS = 10
DEFAULT_HISTORY_MAX_SIZE = 6291456  # 6 MiB
DEFAULT_MAINTENANCE_HISTORY_DAYS = 365


# -------------------- Enums --------------------

class Cipher(StrEnum):
    """Supported encryption ciphers."""
    AES256 = 'aes256'
    CHACHA20 = 'chacha20'
    TWOFISH = 'twofish'


class KdfAlgorithm(StrEnum):
    """Key derivation function algorithms."""
    ARGON2ID = 'argon2id'
    ARGON2D = 'argon2d'
    AES_KDF = 'aeskdf'


# -------------------- KDF Configuration Dataclasses --------------------

@dataclass(frozen=True)
class Argon2Config:
    """KDBX4 Argon2 KDF configuration.

    Attributes:
        variant: Argon2 variant (argon2id or argon2d)
        iterations: Time cost (number of iterations)
        memory_kib: Memory cost in kibibytes (KiB)
        parallelism: Degree of parallelism (threads)
    """
    variant: KdfAlgorithm = KdfAlgorithm.ARGON2ID
    iterations: int = 19
    memory_kib: int = 65536  # 64 MiB
    parallelism: int = 2

    def __post_init__(self):
        if self.variant not in (KdfAlgorithm.ARGON2ID, KdfAlgorithm.ARGON2D):
            raise ValueError(f"Invalid Argon2 variant: {self.variant}")
        if self.iterations < 1:
            raise ValueError("iterations must be at least 1")
        if self.memory_kib < 8:
            raise ValueError("memory_kib must be at least 8")
        if self.parallelism < 1:
            raise ValueError("parallelism must be at least 1")

    @classmethod
    def standard(cls) -> Argon2Config:
        """Standard security preset (KeePass default)."""
        return cls()

    @classmethod
    def high_security(cls) -> Argon2Config:
        """High security preset for sensitive data."""
        return cls(iterations=100, memory_kib=262144, parallelism=4)

    @classmethod
    def fast(cls) -> Argon2Config:
        """Fast preset for testing or low-security scenarios."""
        return cls(iterations=3, memory_kib=16384, parallelism=2)


@dataclass(frozen=True)
class AesKdfConfig:
    """KDBX3 AES-KDF configuration.

    Attributes:
        rounds: Number of AES encryption rounds for key transformation
    """
    rounds: int = 60000  # KeePass default

    def __post_init__(self):
        if self.rounds < 1:
            raise ValueError("rounds must be at least 1")

    @classmethod
    def standard(cls) -> AesKdfConfig:
        """Standard security preset (KeePass default)."""
        return cls()

    @classmethod
    def high_security(cls) -> AesKdfConfig:
        """High security preset for sensitive data."""
        return cls(rounds=6000000)


# Type alias for KDF configuration
KdfConfig = Argon2Config | AesKdfConfig


# -------------------- Helper Functions --------------------

def encode_time_kdbx4(dt: datetime | None = None) -> str:
    """Encode datetime for KDBX4 (base64-encoded binary timestamp).

    KDBX4 uses seconds since 0001-01-01 00:00:00 UTC, stored as 8-byte LE int.

    Args:
        dt: Datetime to encode. If None, uses current UTC time.

    Returns:
        Base64-encoded timestamp string.
    """
    if dt is None:
        dt = datetime.now(timezone.utc)
    epoch = datetime(1, 1, 1, tzinfo=timezone.utc)
    seconds = int((dt - epoch).total_seconds())
    return base64.b64encode(struct.pack('<Q', seconds)).decode('ascii')


def encode_time_kdbx3(dt: datetime | None = None) -> str:
    """Encode datetime for KDBX3 (ISO 8601 string).

    Args:
        dt: Datetime to encode. If None, uses current UTC time.

    Returns:
        ISO 8601 formatted datetime string.
    """
    if dt is None:
        dt = datetime.now(timezone.utc)
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')


def encode_uuid(u: bytes) -> str:
    """Encode UUID bytes as base64 string.

    Args:
        u: 16-byte UUID

    Returns:
        Base64-encoded UUID string.
    """
    return base64.b64encode(u).decode('ascii')


# -------------------- XML Builder --------------------

def build_xml_structure(
    root_group_uuid: bytes,
    version: int = 4,
    database_name: str = DEFAULT_DATABASE_NAME,
) -> etree._ElementTree:
    """Build the XML structure for a new KDBX database.

    Args:
        root_group_uuid: UUID bytes for the root group
        version: KDBX version (3 or 4)
        database_name: Name for the database

    Returns:
        lxml ElementTree containing the KeePass XML structure.
    """
    encode_time = encode_time_kdbx4 if version == 4 else encode_time_kdbx3
    null_uuid = b'\x00' * 16

    xml_root = E.KeePassFile(
        E.Meta(
            E.Generator("pykeepass"),
            E.DatabaseName(database_name),
            E.DatabaseNameChanged(encode_time()),
            E.DatabaseDescription(""),
            E.DatabaseDescriptionChanged(encode_time()),
            E.DefaultUserName(""),
            E.DefaultUserNameChanged(encode_time()),
            E.MaintenanceHistoryDays(str(DEFAULT_MAINTENANCE_HISTORY_DAYS)),
            E.Color(""),
            E.MasterKeyChanged(encode_time()),
            E.MasterKeyChangeRec("-1"),
            E.MasterKeyChangeForce("-1"),
            E.MemoryProtection(
                E.ProtectTitle("False"),
                E.ProtectUserName("False"),
                E.ProtectPassword("True"),
                E.ProtectURL("False"),
                E.ProtectNotes("False"),
            ),
            E.CustomIcons(),
            E.RecycleBinEnabled("True"),
            E.RecycleBinUUID(encode_uuid(null_uuid)),
            E.RecycleBinChanged(encode_time()),
            E.EntryTemplatesGroup(encode_uuid(null_uuid)),
            E.EntryTemplatesGroupChanged(encode_time()),
            E.LastSelectedGroup(encode_uuid(null_uuid)),
            E.LastTopVisibleGroup(encode_uuid(null_uuid)),
            E.HistoryMaxItems(str(DEFAULT_HISTORY_MAX_ITEMS)),
            E.HistoryMaxSize(str(DEFAULT_HISTORY_MAX_SIZE)),
            E.SettingsChanged(encode_time()),
            E.CustomData(),
        ),
        E.Root(
            E.Group(
                E.UUID(encode_uuid(root_group_uuid)),
                E.Name("Root"),
                E.Notes(""),
                E.IconID("48"),
                E.Times(
                    E.LastModificationTime(encode_time()),
                    E.CreationTime(encode_time()),
                    E.LastAccessTime(encode_time()),
                    E.ExpiryTime(encode_time()),
                    E.Expires("False"),
                    E.UsageCount("0"),
                    E.LocationChanged(encode_time()),
                ),
                E.IsExpanded("True"),
                E.DefaultAutoTypeSequence(""),
                E.EnableAutoType("null"),
                E.EnableSearching("null"),
                E.LastTopVisibleEntry(encode_uuid(null_uuid)),
            ),
            E.DeletedObjects(),
        ),
    )

    return etree.ElementTree(xml_root)


# -------------------- KDF Parameter Builders --------------------

def build_kdf_parameters_argon2(kdf: Argon2Config, salt: bytes) -> Container:
    """Build KDBX4 KDF parameters VariantDictionary for Argon2.

    Args:
        kdf: Argon2 configuration
        salt: 32-byte random salt

    Returns:
        Container with VariantDictionary structure.
    """
    kdf_uuid = kdf_uuids['argon2id'] if kdf.variant == KdfAlgorithm.ARGON2ID else kdf_uuids['argon2']

    return Container(
        version=b'\x00\x01',
        dict={
            '$UUID': Container(type=VD_BYTES, key='$UUID', value=kdf_uuid, next_byte=VD_UINT64),
            'I': Container(type=VD_UINT64, key='I', value=kdf.iterations, next_byte=VD_UINT64),
            'M': Container(type=VD_UINT64, key='M', value=kdf.memory_kib * 1024, next_byte=VD_UINT32),
            'P': Container(type=VD_UINT32, key='P', value=kdf.parallelism, next_byte=VD_BYTES),
            'S': Container(type=VD_BYTES, key='S', value=salt, next_byte=VD_UINT32),
            'V': Container(type=VD_UINT32, key='V', value=ARGON2_VERSION, next_byte=0x00),
        }
    )


# -------------------- KDBX Structure Builders --------------------

def build_kdbx4_structure(
    cipher: Cipher = Cipher.AES256,
    kdf: Argon2Config | None = None,
) -> Container:
    """Build a KDBX4 Container structure from scratch.

    Args:
        cipher: Encryption cipher to use
        kdf: Argon2 KDF configuration. If None, uses standard preset.

    Returns:
        Container: KDBX4 structure ready for building.
    """
    if kdf is None:
        kdf = Argon2Config.standard()

    if not isinstance(kdf, Argon2Config):
        raise TypeError(f"KDBX4 requires Argon2Config, got {type(kdf).__name__}")

    # Generate random security values
    master_seed = os.urandom(32)
    kdf_salt = os.urandom(32)
    protected_stream_key = os.urandom(64)
    root_group_uuid = uuid.uuid4().bytes
    encryption_iv = os.urandom(IV_SIZES[cipher])

    # Build XML structure
    xml_tree = build_xml_structure(root_group_uuid, version=4)

    # Build KDF parameters
    kdf_params = build_kdf_parameters_argon2(kdf, kdf_salt)

    # Build the complete KDBX structure
    return Container(
        header=Container(
            value=Container(
                sig1=KDBX_SIG1,
                sig2=KDBX_SIG2,
                sig_check=True,
                minor_version=KDBX4_MINOR_VERSION,
                major_version=KDBX4_MAJOR_VERSION,
                dynamic_header=Container({
                    'cipher_id': Container(id='cipher_id', data=str(cipher)),
                    'compression_flags': Container(id='compression_flags', data=Container(compression=True)),
                    'master_seed': Container(id='master_seed', data=master_seed),
                    'encryption_iv': Container(id='encryption_iv', data=encryption_iv),
                    'kdf_parameters': Container(id='kdf_parameters', data=kdf_params),
                    'end': Container(id='end', data=b''),
                }),
            ),
        ),
        body=Container(
            transformed_key=None,
            master_key=None,
            sha256=None,
            cred_check=None,
            payload=Container(
                inner_header=Container({
                    'protected_stream_id': Container(type='protected_stream_id', data='chacha20'),
                    'protected_stream_key': Container(type='protected_stream_key', data=protected_stream_key),
                    'binary': ListContainer([]),
                    'end': Container(type='end', data=b''),
                }),
                xml=xml_tree,
            ),
        ),
    )


def build_kdbx3_structure(
    cipher: Cipher = Cipher.AES256,
    kdf: AesKdfConfig | None = None,
) -> Container:
    """Build a KDBX3 Container structure from scratch.

    Args:
        cipher: Encryption cipher to use
        kdf: AES-KDF configuration. If None, uses standard preset.

    Returns:
        Container: KDBX3 structure ready for building.
    """
    if kdf is None:
        kdf = AesKdfConfig.standard()

    if not isinstance(kdf, AesKdfConfig):
        raise TypeError(f"KDBX3 requires AesKdfConfig, got {type(kdf).__name__}")

    # Generate random security values
    master_seed = os.urandom(32)
    transform_seed = os.urandom(32)
    protected_stream_key = os.urandom(32)
    stream_start_bytes = os.urandom(32)
    root_group_uuid = uuid.uuid4().bytes
    encryption_iv = os.urandom(IV_SIZES[cipher])

    # Build XML structure
    xml_tree = build_xml_structure(root_group_uuid, version=3)

    # Build the complete KDBX structure
    return Container(
        header=Container(
            value=Container(
                sig1=KDBX_SIG1,
                sig2=KDBX_SIG2,
                sig_check=True,
                minor_version=KDBX3_MINOR_VERSION,
                major_version=KDBX3_MAJOR_VERSION,
                dynamic_header=Container({
                    'cipher_id': Container(id='cipher_id', data=str(cipher)),
                    'compression_flags': Container(id='compression_flags', data=Container(compression=True)),
                    'master_seed': Container(id='master_seed', data=master_seed),
                    'transform_seed': Container(id='transform_seed', data=transform_seed),
                    'transform_rounds': Container(id='transform_rounds', data=kdf.rounds),
                    'encryption_iv': Container(id='encryption_iv', data=encryption_iv),
                    'protected_stream_key': Container(id='protected_stream_key', data=protected_stream_key),
                    'stream_start_bytes': Container(id='stream_start_bytes', data=stream_start_bytes),
                    'protected_stream_id': Container(id='protected_stream_id', data='salsa20'),
                    'end': Container(id='end', data=b''),
                }),
            ),
        ),
        body=Container(
            transformed_key=None,
            master_key=None,
            payload=Container(
                cred_check=None,
                xml=xml_tree,
            ),
        ),
    )


def build_kdbx_structure(
    version: int = 4,
    cipher: Cipher = Cipher.AES256,
    kdf: KdfConfig | None = None,
) -> Container:
    """Build a KDBX Container structure from scratch.

    Unified entry point that dispatches to version-specific builders.

    Args:
        version: KDBX version (3 or 4)
        cipher: Encryption cipher to use
        kdf: KDF configuration. If None, uses appropriate default for version.
            - KDBX4: Argon2Config.standard()
            - KDBX3: AesKdfConfig.standard()

    Returns:
        Container: KDBX structure ready for building.

    Raises:
        ValueError: If version is not 3 or 4.
        TypeError: If KDF type doesn't match version.
    """
    if version == 4:
        if kdf is None:
            kdf = Argon2Config.standard()
        return build_kdbx4_structure(cipher=cipher, kdf=kdf)
    elif version == 3:
        if kdf is None:
            kdf = AesKdfConfig.standard()
        return build_kdbx3_structure(cipher=cipher, kdf=kdf)
    else:
        raise ValueError(f"Unsupported KDBX version: {version}. Must be 3 or 4.")
