"""Copy this distribution into an explicitly chosen Hermes home, without overwrites."""
import argparse
import os
from pathlib import Path
import shutil
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', type=Path, default=Path(os.environ.get('HERMES_HOME', str(Path.home() / '.hermes'))))
    args = parser.parse_args()
    parent = args.home.expanduser().resolve() / 'plugins'
    parent.mkdir(parents=True, exist_ok=True)
    destination = parent / 'apple-passwords'
    if destination.exists() or destination.is_symlink():
        parser.error('apple-passwords is already present; review/remove that copy before installing')
    source = Path(__file__).resolve().parent
    staging = Path(tempfile.mkdtemp(prefix='.apple-passwords-install-', dir=parent))
    try:
        for name in ('__init__.py', 'backend.py', 'source.py', 'cli.py', 'plugin.yaml', 'README.md', 'SECURITY.md', 'VALIDATION.md', 'LICENSE'):
            shutil.copy2(source / name, staging / name)
        shutil.copytree(source / 'skills', staging / 'skills')
        # Never replace an installation created by another process in the meantime.
        destination.mkdir()
        try:
            for item in staging.iterdir():
                shutil.move(str(item), destination / item.name)
        except Exception:
            shutil.rmtree(destination)
            raise
    finally:
        shutil.rmtree(staging)
    print('Installed to ' + str(destination))
    print('Next, in this Hermes profile: hermes plugins enable apple-passwords')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
