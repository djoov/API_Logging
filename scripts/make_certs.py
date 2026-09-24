"""Create the lab CA and per-host server certificates (PHASE 2, HTTPS).

Run on ONE host (the one that keeps the CA key), from the project root:
    python scripts/make_certs.py ca
    python scripts/make_certs.py server --name windows --ip 192.168.56.1 --ip 127.0.0.1 --dns localhost
    python scripts/make_certs.py server --name kali    --ip 192.168.56.10
    python scripts/make_certs.py show

Then copy ONLY secrets/ca.pem, secrets/kali.pem and secrets/kali.key to the Kali host.
Never copy ca.key, never commit secrets/.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from security.tls_certs import CA_CERT, create_ca, create_server_cert, describe_cert  # noqa: E402

DEFAULT_DIR = Path(__file__).resolve().parents[1] / "secrets"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Lab CA and server certificates")
    parser.add_argument("--dir", type=Path, default=DEFAULT_DIR, help="output directory (default: secrets/)")
    sub = parser.add_subparsers(dest="command", required=True)

    ca = sub.add_parser("ca", help="create the lab CA (once)")
    ca.add_argument("--days", type=int, default=365)

    srv = sub.add_parser("server", help="issue a server certificate signed by the lab CA")
    srv.add_argument("--name", required=True, help="host name, e.g. windows or kali (file name prefix)")
    srv.add_argument("--ip", action="append", default=[], help="IP clients use to reach this server (repeatable)")
    srv.add_argument("--dns", action="append", default=[], help="hostname clients use (repeatable)")
    srv.add_argument("--days", type=int, default=365)

    sub.add_parser("show", help="list certificates in the directory")
    args = parser.parse_args(argv)

    try:
        if args.command == "ca":
            path = create_ca(args.dir, days=args.days)
            print(f"created {path} and {path.with_name('ca.key')} (keep ca.key on this host only)")
        elif args.command == "server":
            cert, key = create_server_cert(args.dir, args.dir, args.name, args.ip, args.dns, days=args.days)
            print(f"created {cert} and {key}")
            print(describe_cert(cert))
        else:
            certs = sorted(args.dir.glob("*.pem"))
            if not certs:
                print(f"no certificates in {args.dir}")
            for cert in certs:
                print(describe_cert(cert))
    except (FileExistsError, FileNotFoundError, ValueError) as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2
    if args.command == "server":
        print(f"server .env:  TLS_CERT_FILE=secrets/{args.name}.pem  TLS_KEY_FILE=secrets/{args.name}.key")
        print(f"client .env:  TARGET_SCHEME=https  TLS_CA_FILE=secrets/{CA_CERT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
