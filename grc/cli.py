"""Command line interface for the Secure GRC System.

Usage examples (the database path comes from SECURE_GRC_DB_PATH or --db):

    python -m grc.cli --db demo.db init
    python -m grc.cli --db demo.db seed
    python -m grc.cli --db demo.db list-risks --username j.mensah --password analyst-demo-pass
    python -m grc.cli --db demo.db add-risk --username j.mensah --password analyst-demo-pass \
        --title "New risk" --owner j.mensah --status Open --severity High
    python -m grc.cli --db demo.db audit-log --username a.okafor --password admin-demo-pass

Every command authenticates first. Read commands work for any role. Write
commands are refused for viewers, and the refusal is written to the audit log.
"""

import argparse
import sys

from . import db as db_module
from .config import database_path
from .rbac import PermissionDenied
from .seed import seed_demo_data
from .service import GRCService


def _print_records(records):
    if not records:
        print("(no records)")
        return
    for record in records:
        line = "#{} {} | owner: {} | status: {}".format(
            record["id"], record["title"], record["owner"], record["status"]
        )
        if "severity" in record:
            line += " | severity: {}".format(record["severity"])
        print(line)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="grc", description="Secure GRC System")
    parser.add_argument("--db", default=None, help="path to the SQLite database")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create the database schema")
    sub.add_parser("seed", help="load fictional demo users and records")

    for name in ("list-risks", "list-controls", "list-findings", "audit-log"):
        p = sub.add_parser(name)
        p.add_argument("--username", required=True)
        p.add_argument("--password", required=True)

    p = sub.add_parser("add-risk")
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--title", required=True)
    p.add_argument("--description", default="")
    p.add_argument("--owner", required=True)
    p.add_argument("--status", default="Open")
    p.add_argument("--severity", default="Medium")

    p = sub.add_parser("add-user")
    p.add_argument("--username", required=True, help="admin username")
    p.add_argument("--password", required=True, help="admin password")
    p.add_argument("--new-username", required=True)
    p.add_argument("--new-password", required=True)
    p.add_argument("--role", required=True,
                   choices=("Admin", "GRC Analyst", "Viewer"))

    args = parser.parse_args(argv)
    conn = db_module.connect(args.db or database_path())
    db_module.init_db(conn)
    service = GRCService(conn)

    try:
        if args.command == "init":
            print("Database ready.")
            return 0
        if args.command == "seed":
            seed_demo_data(service)
            print("Demo users and fictional records loaded.")
            return 0

        user = service.login(args.username, args.password)
        if user is None:
            print("Login failed.")
            return 1
        print("Logged in as {} ({}).".format(user["username"], user["role"]))

        if args.command == "list-risks":
            _print_records(service.list_risks(user))
        elif args.command == "list-controls":
            _print_records(service.list_controls(user))
        elif args.command == "list-findings":
            _print_records(service.list_findings(user))
        elif args.command == "audit-log":
            for entry in service.get_audit_log(user):
                print("{ts} | {username} | {action} | {entity} | {outcome} | "
                      "{details}".format(**entry))
        elif args.command == "add-risk":
            record_id = service.create_risk(
                user, args.title, args.description, args.owner,
                args.status, args.severity,
            )
            print("Risk #{} created.".format(record_id))
        elif args.command == "add-user":
            record_id = service.create_user(
                user, args.new_username, args.new_password, args.role)
            print("User #{} created.".format(record_id))
    except PermissionDenied as exc:
        print("Permission denied: {}".format(exc))
        return 2
    except ValueError as exc:
        print("Invalid input: {}".format(exc))
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
