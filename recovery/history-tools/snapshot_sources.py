#!/usr/bin/env python3
"""Retain exact dirty source trees without committing or including ignored secrets/caches."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args])


def files(repo):
    names = set(git(repo, 'ls-files', '-z').split(b'\0'))
    names.update(git(repo, 'ls-files', '--others', '--exclude-standard', '-z').split(b'\0'))
    result = []
    for raw in sorted(names - {b''}):
        name = os.fsdecode(raw)
        path = repo / name
        if not path.exists() and not path.is_symlink():
            continue
        if path.is_symlink():
            data, kind, mode = os.fsencode(os.readlink(path)), 'symlink', 0o777
        else:
            if not path.is_file():
                raise ValueError(f'Unsupported source entry: {path}')
            data, kind = path.read_bytes(), 'file'
            mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
        result.append((name, kind, mode, data))
    return result


def inventory(entries):
    return [{'path': name, 'kind': kind, 'mode': oct(mode), 'bytes': len(data),
             'sha256': hashlib.sha256(data).hexdigest()} for name, kind, mode, data in entries]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--workspace', default='/workspace', type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    manifest = {'identity': 'Base Git SHA plus exact dirty source tree; not a new Git commit', 'repositories': []}
    for name in ['snarkVM', 'snarkOS', 'snarkVM-aerie', 'snarkOS-aerie']:
        repo = args.workspace / name
        before = git(repo, 'status', '--porcelain=v1', '-z')
        entries = files(repo)
        hashes = inventory(entries)
        tree_hash = hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        archive = args.output / f'{name}-{tree_hash}.tar.gz'
        with archive.open('wb') as output, gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w') as tar:
                for relative, kind, mode, data in entries:
                    entry = tarfile.TarInfo(f'{name}/{relative}')
                    entry.mode = mode
                    if kind == 'symlink':
                        entry.type, entry.linkname = tarfile.SYMTYPE, os.fsdecode(data)
                        tar.addfile(entry)
                    else:
                        entry.size = len(data)
                        tar.addfile(entry, io.BytesIO(data))
        if before != git(repo, 'status', '--porcelain=v1', '-z') or hashes != inventory(files(repo)):
            raise RuntimeError(f'{name} changed during snapshot; output is incomplete and must not be used')
        (args.output / f'{name}.diff').write_bytes(git(repo, 'diff', '--binary', 'HEAD'))
        (args.output / f'{name}.files.json').write_text(json.dumps(hashes, indent=2) + '\n')
        manifest['repositories'].append({
            'name': name, 'branch': git(repo, 'branch', '--show-current').decode().strip(),
            'base_commit': git(repo, 'rev-parse', 'HEAD').decode().strip(),
            'source_tree_sha256': tree_hash, 'archive': archive.name,
            'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
            'cargo_lock_sha256': hashlib.sha256((repo / 'Cargo.lock').read_bytes()).hexdigest(),
            'files': len(entries), 'dirty': bool(before),
        })
        print(name, tree_hash, len(entries), flush=True)
    (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    main()
