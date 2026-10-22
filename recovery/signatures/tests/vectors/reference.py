#!/usr/bin/env python3
"""Independently assemble the canonical fixtures with Python's standard library."""
import hashlib
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parent


def u16(n): return struct.pack('<H', n)
def u32(n): return struct.pack('<I', n)
def u64(n): return struct.pack('<Q', n)
def blob(value): return u32(len(value)) + value


def digest(domain, *parts):
    return hashlib.sha3_512(b''.join(u64(len(p)) + p for p in (domain, *parts))).digest()


def main():
    network = bytes([41]) * 64
    policy = bytes([1]) + u32(30) + bytes([1]) + u32(40) + u32(2) + u16(1) + u16(1) + u16(2) + u16(1) + u32(0)
    policy_commitment = digest(b'AleoRecoveryExperimentalPolicy1', network, policy)
    key = u16(1) + u16(1) + blob(bytes(1952))
    source = bytes([1, 0]) + blob(bytes([42]) * 32) + u64(100) + bytes([2]) * 64 + bytes([3]) * 64
    output = bytes([2, 1]) + key + u64(99) + bytes([4]) * 64 + bytes([7]) * 64
    record_id = digest(b'AleoRecoveryExperimentalRecord1', network, source)
    effects = (b'AleoRecoveryEffects1' + network + u16(1) + u16(1) + policy_commitment + bytes([0]) + u32(0) + u32(100)
               + bytes([1]) * 64 + blob(b'credits.aleo') + u32(1) + record_id + u32(1) + output + u64(1))
    key_id = digest(b'AleoRecoveryExperimentalKey1', network, u16(1), u16(1), bytes(1952))
    statement = b'AleoRecoveryAuthorization1' + bytes([1]) + u16(0) + key + key_id + blob(effects)
    vectors = {'canonical-effects': effects, 'canonical-statement': statement,
               'canonical-digests': record_id + key_id + digest(b'AleoRecoveryExperimentalTransaction1', effects)}
    for name, value in vectors.items():
        assert (ROOT / (name + '.bin')).read_bytes() == value, name
        print(name, hashlib.sha256(value).hexdigest())


if __name__ == '__main__':
    main()
