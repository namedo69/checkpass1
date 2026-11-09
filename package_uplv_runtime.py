"""Build a credential-free portable runtime from an explicit UpLv source tree."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil


def package(source, destination):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if destination.exists():
        raise ValueError('Destination must be new; will not overwrite an existing runtime')
    if not (source / 'pve_runtime' / 'vendor' / 'manifest.json').is_file():
        raise ValueError('Not an UpLv production source tree')
    destination.mkdir(parents=True)
    manifest = {}
    for name in ('pve_runtime', 'pve_backend'):
        for path in (source / name).rglob('*'):
            relative = path.relative_to(source)
            if (not path.is_file() or any(p in ('_data', '__pycache__', '.git') for p in relative.parts)
                    or path.suffix not in ('.py', '.pyc', '.json', '.hex')):
                continue
            if path.suffix == '.pyc' and 'vendor' not in relative.parts:
                continue
            output = destination / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, output)
            manifest[relative.as_posix()] = hashlib.sha256(output.read_bytes()).hexdigest()
    (destination / 'bundle_manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    return len(manifest)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True)
    parser.add_argument('--destination', default='uplv_runtime')
    args = parser.parse_args()
    print(f'Packaged {package(args.source, args.destination)} files (no device caches)')
