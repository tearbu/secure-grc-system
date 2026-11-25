# Secure GRC System

A small governance, risk, and compliance register that I designed and built
with the security controls written down and tested, as a working answer to a
simple question: if a GRC system holds the most sensitive map in an
organization, what does it look like to build one carefully?

## Story

I read a LinkedIn post by Svein Waage that stuck with me. His point was that
a GRC system is where an organization stores its most sensitive overview:
every open vulnerability, every security control, every risk assessment, and
the people responsible for each one. A threat actor with access to that
system does not have to go looking for weaknesses. The system is the menu.

His warning was about GRC tools generated quickly with AI coding tools, by
people without the architecture, secure development, vulnerability handling,
monitoring, and incident response experience to control what they built. The
risk, as he put it, is losing control of where your data ends up.

I have a GRC control tracker in my portfolio already. This project is the
other half of that post: a GRC register where I made the security decisions
myself, wrote them down, and tested the parts that usually get skipped,
especially the denials. It is a portfolio scale system, not a commercial GRC
platform, and I say plainly in the self-assessment what it does not do.

## How

The system is a Python application with no third party dependencies. It runs
on the standard library alone and stores everything in one local SQLite
file. I gave it a command line interface on purpose: zero network listeners,
zero attack surface beyond the inputs themselves.

The register holds three record types:

- **Risks**, with owner, status, and severity.
- **Controls**, with owner, status, and a framework reference.
- **Findings** (vulnerabilities and audit issues), with owner, status,
  severity, and source.

Around those records I built four controls:

1. **Accounts with real password storage.** Passwords are hashed with
   scrypt and a fresh random salt per password. Nothing is stored in
   plaintext, and I do not use fast hashes like MD5 or plain SHA for
   passwords anywhere.
2. **Role based access control with three roles.** Viewers read only. GRC
   Analysts create and edit records and can read the audit log. Admins do
   all of that plus user management. The check runs in the service layer on
   every operation, so no interface can skip it.
3. **An append-only audit log.** Logins, failed logins, record creates and
   edits, user creation, and every permission denial are recorded with a
   timestamp and the actor. SQLite triggers abort any update or delete
   against the log, so the rule holds even if application code misbehaves.
4. **Validated inputs and parameterized queries.** Severities and statuses
   come from fixed lists, required fields are enforced, and every SQL
   statement binds its values. A test stores a classic injection string as
   a record title and confirms it lands as inert text.

Configuration is one environment variable for the database path. The
.env.example file holds no real values, because the app needs no keys: it
makes no external network calls and sends data nowhere.

### Decisions

The full reasoning lives in [docs/security-decisions.md](docs/security-decisions.md).
The short version:

- **scrypt over convenience.** Logins are slower by design. A stolen
  database should not become a list of working passwords.
- **Denials are logged, not just refused.** A permission system that fails
  silently teaches you nothing. Every denied attempt in the demo below is
  sitting in the audit log with the role that tried it.
- **Append-only enforced by the database, not by good intentions.** I put
  the trigger in SQLite so the guarantee does not depend on my code being
  bug free.
- **No web server, no dependencies, no external calls.** Each of those is a
  decision, not an omission. The register stays in one local file, which is
  my answer to the question of where the data ends up.
- **No record deletion.** Records close or get remediated by status. The
  register keeps its history.

The threat model is in [docs/threat-model.md](docs/threat-model.md), and my
self-assessment against the concerns in the post, including the gaps, is in
[docs/self-assessment.md](docs/self-assessment.md).

### Running it

```bash
python run_demo.py                          # full demo on a disposable database
python -m unittest discover -s tests -v     # the test suite
python -m grc.cli --db demo.db seed         # load fictional demo data
python -m grc.cli --db demo.db list-risks --username r.patel --password viewer-demo-pass
```

The demo accounts and records are fictional and exist only for the demo
database, which the demo script deletes when it finishes.

## Output

Real output from `python run_demo.py`, captured from an actual run:

```text
== Seeding fictional demo data ==
  Users created: a.okafor (Admin), j.mensah (GRC Analyst), r.patel (Viewer)
  Seeded 2 risks, 2 controls, 2 findings (all fictional).

== Login checks ==
  Login with a wrong password returned: None
  Login with the correct password returned user: j.mensah

== What each role can do ==
  OK      Viewer lists risks (read only role)
          #1 Vendor remote access without expiry dates [High]
          #2 Risk register held in a shared spreadsheet [Medium]
  DENIED  Viewer tries to create a risk (role 'Viewer' is not allowed to perform 'create')
  OK      Analyst creates a risk
  OK      Analyst edits the new risk status
  DENIED  Analyst tries to create a user account (role 'GRC Analyst' is not allowed to perform 'manage_users')
  DENIED  Viewer tries to read the audit log (role 'Viewer' is not allowed to perform 'view_audit')
  OK      Admin creates a user account

== Audit log (append-only) ==
   1 2026-11-25T20:46:16Z bootstrap create_user  users     success  created a.okafor with role Admin
   2 2026-11-25T20:46:16Z a.okafor  login        users     success  role Admin
   3 2026-11-25T20:46:16Z a.okafor  create_user  users     success  created j.mensah with role GRC Analyst
   4 2026-11-25T20:46:16Z j.mensah  login        users     success  role GRC Analyst
   5 2026-11-25T20:46:16Z a.okafor  create_user  users     success  created r.patel with role Viewer
   6 2026-11-25T20:46:16Z r.patel   login        users     success  role Viewer
   7 2026-11-25T20:46:16Z j.mensah  create       risks     success  Vendor remote access without expiry dates
   8 2026-11-25T20:46:16Z j.mensah  create       risks     success  Risk register held in a shared spreadsheet
   9 2026-11-25T20:46:16Z j.mensah  create       controls  success  Quarterly access review for privileged accounts
  10 2026-11-25T20:46:16Z j.mensah  create       controls  success  Audit log review, weekly
  11 2026-11-25T20:46:16Z j.mensah  create       findings  success  Dormant service account with admin rights
  12 2026-11-25T20:46:16Z j.mensah  create       findings  success  Shared mailbox with five delegates and no owner
  13 2026-11-25T20:46:16Z j.mensah  login        users     failure  invalid credentials
  14 2026-11-25T20:46:16Z j.mensah  login        users     success  role GRC Analyst
  15 2026-11-25T20:46:16Z r.patel   create       risks     denied   role Viewer attempted create
  16 2026-11-25T20:46:16Z j.mensah  create       risks     success  Unreviewed admin group membership
  17 2026-11-25T20:46:16Z j.mensah  edit         risks     success  status
  18 2026-11-25T20:46:16Z j.mensah  manage_users users     denied   role GRC Analyst attempted manage_users
  19 2026-11-25T20:46:16Z r.patel   view_audit   audit_log denied   role Viewer attempted view_audit
  20 2026-11-25T20:46:16Z a.okafor  create_user  users     success  created t.nguyen with role Viewer

Demo database deleted.
```

The test suite runs 23 tests and passes:

```text
.......................
----------------------------------------------------------------------
Ran 23 tests in 7.142s

OK
```

The tests cover password hashing and verification, login success and
failure, RBAC allows and denials for all three roles, audit entries being
written for actions and for denials, the audit log refusing updates and
deletes at the database level, input validation, and an injection string
stored as inert data.

## Worth

Most small GRC tools I have seen, including ones generated in an afternoon,
get the records right and the protection wrong: plaintext or weakly hashed
passwords, one all powerful account, no log of who changed what, and data
synced to services nobody chose on purpose. This project is my evidence that
I think about the protection first. I can walk an interviewer through the
threat model, point at the exact test that proves a viewer cannot create a
record, and show the audit log entry that denial produced.

It also pairs with my other GRC work. The control tracker shows I can model
controls and track remediation. This one shows I can build the register
itself like the sensitive system it is, and write down what it still cannot
do: no SSO or MFA, no alerting, no tested backup story. Those gaps are
listed in the self-assessment because naming them is part of the work.

## License

MIT. See [LICENSE](LICENSE).
