# Security decisions

This document records the choices I made while building this system, why I
made them, and what each one costs. I wrote it because the post that prompted
this project argued that the danger of a quickly generated GRC tool is not
any single bug. The danger is that nobody made, or wrote down, the decisions
at all.

## Password storage: scrypt, salted, never plaintext

I hash passwords with hashlib.scrypt using a fresh 16 byte random salt per
password, and I store the parameters and salt alongside the hash so
verification replays the same work. I compare digests with
hmac.compare_digest.

Trade-off: scrypt makes each login measurably slower and makes bulk user
creation slower too, which the test suite runtime shows. I accept that cost
because a GRC database is exactly the file an attacker wants, and a stolen
copy should not turn into working passwords. I ruled out MD5 and plain SHA
family hashes for passwords completely. They are fast by design, which is
the opposite of what password storage needs.

## Access control: three roles, checked in the service layer

I defined three roles. Viewer reads only. GRC Analyst reads, creates, and
edits register records and can read the audit log. Admin does all of that
plus user management.

Every operation in the service layer calls the permission check before it
touches data, and a denial is written to the audit log before the exception
escapes. I put the check in the service layer rather than in the CLI so that
no interface can bypass it: any future front end that calls the service gets
the same enforcement.

Trade-off: three roles are coarse. A real organization would want scope
limits, for example an analyst who can only edit records for their own
department. I kept the model small enough to test exhaustively instead, and
I test the denials as carefully as the allows, because a permission system
that is only tested on its happy path is a guess.

## Audit log: append-only, enforced by the database

The audit log records logins (success and failure), record creates and
edits, user creation, and every permission denial. Entries carry a UTC
timestamp, the username, the action, the entity, and the outcome.

I enforced append-only behavior with SQLite triggers that abort any UPDATE
or DELETE on the audit table. That matters: the rule does not depend on
application code behaving. Even a buggy or hostile code path cannot rewrite
history through the database connection. Tests attempt both an update and a
delete and confirm the database refuses them.

Trade-off: an append-only log grows forever and mistakes cannot be cleaned
up. For a register of this size that is the right trade. Evidence you can
edit is not evidence.

## Data handling: parameterized queries and validated inputs, always

Every SQL statement in the codebase uses bound parameters. Table and column
names in the few dynamic statements come from fixed internal lists, never
from user input. On top of that, the service layer validates before storage:
severities and statuses must come from fixed lists, required text must be
present, and text is length capped.

Trade-off: validation rejects some free form input a real team might want,
for example a custom severity label. I prefer a register whose fields stay
comparable over time to one that accepts anything.

## Configuration: environment variables, no secrets in code

The only configuration is the database path, read from the
SECURE_GRC_DB_PATH environment variable. The .env.example file shows the
variable name and a placeholder path. It contains no credentials because the
application needs none.

## What the application intentionally does not do

- **No external network calls.** The app never phones home, never syncs,
  and never sends register data to an analytics or error reporting service.
  This is my direct answer to the question the prompting post raised: where
  does your data end up? Here, it ends up in one local file, and nowhere
  else.
- **No third party dependencies.** The whole system runs on the Python
  standard library. There is no dependency tree to audit, pin, or be
  surprised by.
- **No SSO, SAML, or MFA.** I did not bolt on claims I cannot support at
  this scale. Authentication is local passwords done carefully, and the
  self-assessment names federation and MFA as gaps.
- **No web server.** I chose a CLI so the attack surface stays at zero
  network listeners. A web front end would need transport security, session
  handling, and browser protections that deserve their own project.
- **No record deletion.** Records are closed or remediated by status, never
  deleted, so the register keeps its own history alongside the audit log.
