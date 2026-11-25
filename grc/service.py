"""Service layer: authentication, register operations, and the audit log.

This is the only layer the CLI and the demo talk to. It enforces role based
access control on every operation, validates every input before it reaches
the database, and writes an audit entry for logins, record changes, user
management, and permission denials.
"""

from datetime import datetime, timezone

from . import auth, rbac
from .rbac import PermissionDenied

SEVERITIES = ("Low", "Medium", "High", "Critical")
RISK_STATUSES = ("Open", "In Progress", "Closed")
CONTROL_STATUSES = ("Implemented", "Partially Implemented", "Planned")
FINDING_STATUSES = ("Open", "Remediated", "Accepted")

_MAX_TEXT = 500


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean_text(value, field, required=True):
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValueError("{} must be text".format(field))
    value = value.strip()
    if required and not value:
        raise ValueError("{} is required".format(field))
    if len(value) > _MAX_TEXT:
        raise ValueError("{} is longer than {} characters".format(field, _MAX_TEXT))
    return value


def _clean_choice(value, field, choices):
    value = _clean_text(value, field)
    if value not in choices:
        raise ValueError(
            "{} must be one of: {}".format(field, ", ".join(choices))
        )
    return value


class GRCService:
    """All application operations, with RBAC and auditing enforced."""

    def __init__(self, conn):
        self.conn = conn

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------
    def _audit(self, username, action, entity="", entity_id=None,
               outcome="success", details=""):
        self.conn.execute(
            "INSERT INTO audit_log (ts, username, action, entity, entity_id,"
            " outcome, details) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (_now(), username, action, entity, entity_id, outcome, details),
        )
        self.conn.commit()

    def get_audit_log(self, user):
        """Return all audit entries, oldest first. Analysts and admins only."""
        self._require(user, "view_audit", "audit_log")
        rows = self.conn.execute(
            "SELECT id, ts, username, action, entity, entity_id, outcome,"
            " details FROM audit_log ORDER BY id ASC"
        ).fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------------
    # Access control helper
    # ------------------------------------------------------------------
    def _require(self, user, action, entity=""):
        try:
            rbac.require(user["role"], action)
        except PermissionDenied:
            self._audit(
                user["username"], action, entity, None, "denied",
                "role {} attempted {}".format(user["role"], action),
            )
            raise

    # ------------------------------------------------------------------
    # Users and login
    # ------------------------------------------------------------------
    def create_user(self, actor, username, password, role):
        """Create a user account. Only an admin may call this, except when
        bootstrapping the very first account on an empty database."""
        username = _clean_text(username, "username")
        role = _clean_choice(role, "role", rbac.ROLES)
        user_count = self.conn.execute(
            "SELECT COUNT(*) AS n FROM users"
        ).fetchone()["n"]
        if user_count > 0:
            if actor is None:
                raise PermissionDenied("an admin account is required")
            self._require(actor, "manage_users", "users")
        existing = self.conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if existing is not None:
            raise ValueError("username '{}' already exists".format(username))
        password_hash = auth.hash_password(password)
        cursor = self.conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at)"
            " VALUES (?, ?, ?, ?)",
            (username, password_hash, role, _now()),
        )
        self.conn.commit()
        actor_name = actor["username"] if actor else "bootstrap"
        self._audit(actor_name, "create_user", "users", cursor.lastrowid,
                    "success", "created {} with role {}".format(username, role))
        return cursor.lastrowid

    def login(self, username, password):
        """Authenticate and return the user record, or None on failure.

        Both outcomes are written to the audit log.
        """
        row = self.conn.execute(
            "SELECT id, username, password_hash, role FROM users"
            " WHERE username = ?",
            (username,),
        ).fetchone()
        if row is None or not auth.verify_password(password, row["password_hash"]):
            self._audit(username, "login", "users", None, "failure",
                        "invalid credentials")
            return None
        user = {"id": row["id"], "username": row["username"], "role": row["role"]}
        self._audit(username, "login", "users", row["id"], "success",
                    "role {}".format(row["role"]))
        return user

    # ------------------------------------------------------------------
    # Register records: risks, controls, findings
    # ------------------------------------------------------------------
    def _create_record(self, user, table, fields):
        self._require(user, "create", table)
        now = _now()
        columns = list(fields.keys()) + ["created_by", "created_at", "updated_at"]
        values = list(fields.values()) + [user["username"], now, now]
        placeholders = ", ".join("?" for _ in columns)
        cursor = self.conn.execute(
            "INSERT INTO {} ({}) VALUES ({})".format(
                table, ", ".join(columns), placeholders
            ),
            values,
        )
        self.conn.commit()
        self._audit(user["username"], "create", table, cursor.lastrowid,
                    "success", fields["title"])
        return cursor.lastrowid

    def _update_record(self, user, table, record_id, fields):
        self._require(user, "edit", table)
        existing = self.conn.execute(
            "SELECT id FROM {} WHERE id = ?".format(table), (record_id,)
        ).fetchone()
        if existing is None:
            raise ValueError("no {} record with id {}".format(table, record_id))
        assignments = ", ".join("{} = ?".format(name) for name in fields)
        values = list(fields.values()) + [_now(), record_id]
        self.conn.execute(
            "UPDATE {} SET {}, updated_at = ? WHERE id = ?".format(
                table, assignments
            ),
            values,
        )
        self.conn.commit()
        self._audit(user["username"], "edit", table, record_id, "success",
                    ", ".join(sorted(fields.keys())))

    def _list_records(self, user, table):
        self._require(user, "read", table)
        rows = self.conn.execute(
            "SELECT * FROM {} ORDER BY id ASC".format(table)
        ).fetchall()
        return [dict(row) for row in rows]

    # Risks
    def create_risk(self, user, title, description, owner, status, severity):
        return self._create_record(user, "risks", {
            "title": _clean_text(title, "title"),
            "description": _clean_text(description, "description", required=False),
            "owner": _clean_text(owner, "owner"),
            "status": _clean_choice(status, "status", RISK_STATUSES),
            "severity": _clean_choice(severity, "severity", SEVERITIES),
        })

    def update_risk(self, user, record_id, **fields):
        cleaned = {}
        if "title" in fields:
            cleaned["title"] = _clean_text(fields["title"], "title")
        if "description" in fields:
            cleaned["description"] = _clean_text(
                fields["description"], "description", required=False)
        if "owner" in fields:
            cleaned["owner"] = _clean_text(fields["owner"], "owner")
        if "status" in fields:
            cleaned["status"] = _clean_choice(
                fields["status"], "status", RISK_STATUSES)
        if "severity" in fields:
            cleaned["severity"] = _clean_choice(
                fields["severity"], "severity", SEVERITIES)
        if not cleaned:
            raise ValueError("nothing to update")
        self._update_record(user, "risks", record_id, cleaned)

    def list_risks(self, user):
        return self._list_records(user, "risks")

    # Controls
    def create_control(self, user, title, description, owner, status,
                       framework_ref=""):
        return self._create_record(user, "controls", {
            "title": _clean_text(title, "title"),
            "description": _clean_text(description, "description", required=False),
            "owner": _clean_text(owner, "owner"),
            "status": _clean_choice(status, "status", CONTROL_STATUSES),
            "framework_ref": _clean_text(
                framework_ref, "framework_ref", required=False),
        })

    def update_control(self, user, record_id, **fields):
        cleaned = {}
        if "title" in fields:
            cleaned["title"] = _clean_text(fields["title"], "title")
        if "description" in fields:
            cleaned["description"] = _clean_text(
                fields["description"], "description", required=False)
        if "owner" in fields:
            cleaned["owner"] = _clean_text(fields["owner"], "owner")
        if "status" in fields:
            cleaned["status"] = _clean_choice(
                fields["status"], "status", CONTROL_STATUSES)
        if "framework_ref" in fields:
            cleaned["framework_ref"] = _clean_text(
                fields["framework_ref"], "framework_ref", required=False)
        if not cleaned:
            raise ValueError("nothing to update")
        self._update_record(user, "controls", record_id, cleaned)

    def list_controls(self, user):
        return self._list_records(user, "controls")

    # Findings
    def create_finding(self, user, title, description, owner, status,
                       severity, source=""):
        return self._create_record(user, "findings", {
            "title": _clean_text(title, "title"),
            "description": _clean_text(description, "description", required=False),
            "owner": _clean_text(owner, "owner"),
            "status": _clean_choice(status, "status", FINDING_STATUSES),
            "severity": _clean_choice(severity, "severity", SEVERITIES),
            "source": _clean_text(source, "source", required=False),
        })

    def update_finding(self, user, record_id, **fields):
        cleaned = {}
        if "title" in fields:
            cleaned["title"] = _clean_text(fields["title"], "title")
        if "description" in fields:
            cleaned["description"] = _clean_text(
                fields["description"], "description", required=False)
        if "owner" in fields:
            cleaned["owner"] = _clean_text(fields["owner"], "owner")
        if "status" in fields:
            cleaned["status"] = _clean_choice(
                fields["status"], "status", FINDING_STATUSES)
        if "severity" in fields:
            cleaned["severity"] = _clean_choice(
                fields["severity"], "severity", SEVERITIES)
        if "source" in fields:
            cleaned["source"] = _clean_text(
                fields["source"], "source", required=False)
        if not cleaned:
            raise ValueError("nothing to update")
        self._update_record(user, "findings", record_id, cleaned)

    def list_findings(self, user):
        return self._list_records(user, "findings")
