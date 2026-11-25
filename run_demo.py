"""One run demonstration of the Secure GRC System.

Seeds fictional data in a temporary database, logs in as each role, performs
allowed and denied actions, prints the results, then prints the audit log so
a reviewer can see access control and logging working together. The temporary
database is deleted when the demo finishes.

Run it with:  python run_demo.py
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from grc import db as db_module
from grc.rbac import PermissionDenied
from grc.seed import seed_demo_data
from grc.service import GRCService


def attempt(label, fn):
    try:
        result = fn()
    except PermissionDenied as exc:
        print("  DENIED  {} ({})".format(label, exc))
        return None
    print("  OK      {}".format(label))
    return result


def main():
    fd, path = tempfile.mkstemp(prefix="secure-grc-demo-", suffix=".db")
    os.close(fd)
    try:
        conn = db_module.connect(path)
        db_module.init_db(conn)
        service = GRCService(conn)

        print("== Seeding fictional demo data ==")
        users = seed_demo_data(service)
        admin = users["Admin"]
        analyst = users["GRC Analyst"]
        viewer = users["Viewer"]
        print("  Users created: a.okafor (Admin), j.mensah (GRC Analyst), "
              "r.patel (Viewer)")
        print("  Seeded 2 risks, 2 controls, 2 findings (all fictional).")

        print()
        print("== Login checks ==")
        bad = service.login("j.mensah", "wrong-password")
        print("  Login with a wrong password returned: {}".format(bad))
        good = service.login("j.mensah", "analyst-demo-pass")
        print("  Login with the correct password returned user: {}".format(
            good["username"]))

        print()
        print("== What each role can do ==")
        risks = attempt("Viewer lists risks (read only role)",
                        lambda: service.list_risks(viewer))
        if risks:
            for risk in risks:
                print("          #{} {} [{}]".format(
                    risk["id"], risk["title"], risk["severity"]))
        attempt("Viewer tries to create a risk",
                lambda: service.create_risk(
                    viewer, "Viewer should not create this", "", "r.patel",
                    "Open", "Low"))
        new_id = attempt("Analyst creates a risk",
                         lambda: service.create_risk(
                             analyst, "Unreviewed admin group membership",
                             "Membership of the server admin group has no "
                             "review date.", "j.mensah", "Open", "High"))
        if new_id:
            attempt("Analyst edits the new risk status",
                    lambda: service.update_risk(
                        analyst, new_id, status="In Progress"))
        attempt("Analyst tries to create a user account",
                lambda: service.create_user(
                    analyst, "sneaky.account", "sneaky-pass-123", "Admin"))
        attempt("Viewer tries to read the audit log",
                lambda: service.get_audit_log(viewer))
        attempt("Admin creates a user account",
                lambda: service.create_user(
                    admin, "t.nguyen", "viewer2-demo-pass", "Viewer"))

        print()
        print("== Audit log (append-only) ==")
        for entry in service.get_audit_log(admin):
            print("  {id:>2} {ts} {username:<9} {action:<12} {entity:<9} "
                  "{outcome:<8} {details}".format(**entry))
    finally:
        try:
            conn.close()
        except Exception:
            pass
        os.unlink(path)
        print()
        print("Demo database deleted.")


if __name__ == "__main__":
    main()
