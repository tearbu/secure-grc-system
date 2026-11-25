"""Role based access control.

Three roles exist, and every action in the service layer checks the caller's
role against this table before it touches data:

- Viewer: read only. Cannot create, edit, manage users, or read the audit log.
- GRC Analyst: read, create, and edit register records, and read the audit log.
  Cannot manage user accounts.
- Admin: everything an analyst can do, plus user management.

Denials are enforced here and in the service layer, and every denial is
written to the audit log by the service layer before the exception escapes.
"""

ROLES = ("Admin", "GRC Analyst", "Viewer")

PERMISSIONS = {
    "Viewer": {"read"},
    "GRC Analyst": {"read", "create", "edit", "view_audit"},
    "Admin": {"read", "create", "edit", "view_audit", "manage_users"},
}


class PermissionDenied(Exception):
    """Raised when a role attempts an action it is not allowed to perform."""


def has_permission(role, action):
    """Return True when the role is allowed to perform the action."""
    return action in PERMISSIONS.get(role, set())


def require(role, action):
    """Raise PermissionDenied when the role may not perform the action."""
    if not has_permission(role, action):
        raise PermissionDenied(
            "role '{}' is not allowed to perform '{}'".format(role, action)
        )
