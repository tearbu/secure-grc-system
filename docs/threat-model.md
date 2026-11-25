# Threat model

I wrote this threat model before I wrote the application code, because the
whole point of this project is that a GRC system is not an ordinary CRUD app.
The data inside it changes what an attacker can do with it.

## Assets

The primary asset is the register itself: the combined list of risks,
controls, and open findings, with owners and statuses.

- **The risk register is an attack map.** It lists what the organization
  already knows is weak, how severe each weakness is, and whether anyone has
  fixed it yet. A finding marked Critical and Open tells an attacker exactly
  where to push first.
- **The control list shows the gaps between controls.** A control marked
  Planned or Partially Implemented is an admission that a safeguard is not
  fully in place. Read together with the findings, it shows which doors are
  watched and which are not.
- **Owner fields name the people responsible.** That is useful for phishing
  and social engineering, because it identifies who holds which duty.
- **User credentials** protect all of the above. A single admin account is
  the keys to the whole register.
- **The audit log is evidence.** If an attacker or a dishonest insider can
  rewrite it, the organization loses the ability to prove who saw or changed
  what.

## Threat actors

- **External attacker with stolen credentials.** Buys or phishes one
  password and reads the full register, or worse, edits it to hide a finding.
- **Curious or malicious insider.** A staff member with a legitimate low
  privilege account tries to read or change records outside their role, for
  example closing a finding assigned to them or reading risks they have no
  business seeing.
- **Insider covering their tracks.** Someone with application access tries
  to delete or edit audit entries after doing something they should not have.
- **Automated probing.** Injection strings and scripted login attempts
  against any input field.

## Trust boundaries

- Between the user and the service layer: nothing the user sends is trusted
  until the service layer has checked the role, validated the input, and
  parameterized the query.
- Between the application and the database file: the database enforces its
  own rules through constraints and triggers, so a bug in application code
  cannot quietly rewrite audit history.
- Between the application and the outside world: there is no boundary to
  defend because the application makes no external network calls and sends
  data nowhere. The register stays on the machine it runs on.

## Main abuse cases and the control I chose for each

1. **Stolen credentials used to read the whole register.**
   Controls: passwords hashed with scrypt and a per user salt, so a stolen
   database does not hand over usable passwords. Login failures are written
   to the audit log, so repeated guessing is visible. Roles limit what one
   account can see and do, so a stolen viewer account cannot change records.

2. **Insider overreach: a viewer or analyst acting outside their role.**
   Controls: every operation checks the role in the service layer before it
   touches data. Viewers cannot create or edit anything. Analysts cannot
   manage user accounts. Every denied attempt is written to the audit log
   with the role that tried it, so overreach leaves a record instead of
   passing silently.

3. **Exfiltration of the risk register itself.**
   Controls: the application has no export to external services, no network
   calls, and no third party sharing of any kind. The register exists in one
   local database file. Access to that file is an operating system concern,
   and I say so plainly in the self-assessment instead of pretending the app
   solves it.

4. **Tampering with the audit log to hide an action.**
   Controls: the audit log is append-only. SQLite triggers abort any UPDATE
   or DELETE against it, and the application code contains no path that
   modifies past entries. Tests prove both the update and the delete are
   refused at the database level.

5. **SQL injection through a title or description field.**
   Controls: every query is parameterized, and a test stores a classic
   injection string as a record title and confirms it lands as inert text
   while the table survives.

6. **Silent changes to records.**
   Controls: creates and edits write audit entries with the actor, the
   record, and the fields changed, so the history of a risk or finding can
   be reconstructed from the log.

## What this model does not cover

This is a portfolio scale system that runs locally for one organization at a
time. It does not model multi tenant hosting, network attackers between a
browser and a server (there is no server), or compromise of the machine the
database sits on. Those limits are stated again in the self-assessment.
