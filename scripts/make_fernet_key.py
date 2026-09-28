"""Create the shared application-layer (Fernet) key for Phase 3/4, or show its fingerprint.

    python scripts/make_fernet_key.py              # creates secrets/fernet.key (refuses to overwrite)
    python scripts/make_fernet_key.py --show       # prints the key_id of the existing key

The same key must exist on every host that may DECRYPT payloads (Test D). Copy it only over the
lab network (scp), never through git. A host WITHOUT the key is the Test C situation: it can carry
and store the ciphertext but cannot read it.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from security.payload_crypto import PayloadCryptoError, key_id, load_key, write_key_file  # noqa: E402

DEFAULT_FILE = Path(__file__).resolve().parents[1] / "secrets" / "fernet.key"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create or inspect the lab Fernet key")
    parser.add_argument("--file", type=Path, default=DEFAULT_FILE)
    parser.add_argument("--show", action="store_true", help="only print the key_id of the existing key")
    args = parser.parse_args(argv)
    try:
        if args.show:
            print(f"{args.file}: key_id={key_id(load_key(args.file))}")
            return 0
        key = write_key_file(args.file)
    except (FileExistsError, PayloadCryptoError) as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2
    print(f"created {args.file}  key_id={key_id(key)}")
    print("set on each host that may decrypt:  FERNET_KEY_FILE=secrets/fernet.key")
    return 0


if __name__ == "__main__":
    sys.exit(main())
