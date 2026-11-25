"""Fictional seed data for demos and tests.

Every record here is invented for demonstration. The company, people, and
systems are fictional. The demo account passwords below exist only so the
demo can log in as each role against a disposable local database; they are
not used anywhere else and the demo database is deleted after each run.
"""

DEMO_USERS = (
    ("a.okafor", "admin-demo-pass", "Admin"),
    ("j.mensah", "analyst-demo-pass", "GRC Analyst"),
    ("r.patel", "viewer-demo-pass", "Viewer"),
)

SEED_RISKS = (
    {
        "title": "Vendor remote access without expiry dates",
        "description": "Three vendor accounts on the finance platform have no "
                       "expiry date and were last reviewed over a year ago.",
        "owner": "j.mensah",
        "status": "Open",
        "severity": "High",
    },
    {
        "title": "Risk register held in a shared spreadsheet",
        "description": "The current register has no access logging, so reads "
                       "of the full risk picture cannot be traced.",
        "owner": "a.okafor",
        "status": "In Progress",
        "severity": "Medium",
    },
)

SEED_CONTROLS = (
    {
        "title": "Quarterly access review for privileged accounts",
        "description": "Privileged group membership is reviewed every quarter "
                       "and stale accounts are removed.",
        "owner": "j.mensah",
        "status": "Implemented",
        "framework_ref": "Access control, review of user access rights",
    },
    {
        "title": "Audit log review, weekly",
        "description": "The append-only audit log is reviewed weekly for "
                       "denied actions and failed logins.",
        "owner": "a.okafor",
        "status": "Partially Implemented",
        "framework_ref": "Logging and monitoring",
    },
)

SEED_FINDINGS = (
    {
        "title": "Dormant service account with admin rights",
        "description": "A service account unused for 11 months still holds "
                       "administrator rights on the reporting server.",
        "owner": "j.mensah",
        "status": "Open",
        "severity": "Critical",
        "source": "Quarterly access review",
    },
    {
        "title": "Shared mailbox with five delegates and no owner",
        "description": "A shared mailbox used for vendor invoices has five "
                       "delegates and no named accountable owner.",
        "owner": "r.patel",
        "status": "Open",
        "severity": "Low",
        "source": "Internal audit sample",
    },
)


def seed_demo_data(service):
    """Create the demo users and register records. Returns the user dicts."""
    users = {}
    admin = None
    for username, password, role in DEMO_USERS:
        service.create_user(admin, username, password, role)
        user = service.login(username, password)
        users[role] = user
        if role == "Admin":
            admin = user
    analyst = users["GRC Analyst"]
    for risk in SEED_RISKS:
        service.create_risk(analyst, **risk)
    for control in SEED_CONTROLS:
        service.create_control(analyst, **control)
    for finding in SEED_FINDINGS:
        service.create_finding(analyst, **finding)
    return users
