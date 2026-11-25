# Self-assessment

I assessed this system against the concerns raised in the LinkedIn post by
Svein Waage that prompted the project. His argument, in short: a GRC system
holds the most sensitive map an organization has, so building one without
real control over architecture, secure development, vulnerability handling,
monitoring, and incident response means losing control of where that data
ends up. Here is where this build stands against each concern, including
where it falls short.

## Architecture control

**Standing: addressed at this scale.** I designed the layering myself:
storage, authentication, access control, and a service layer that every
interface must go through. I can explain every data flow in the system
because there are only a few: user input enters the service layer, gets
checked and validated, and lands in one local SQLite file. There is no
hosted component and no data flow to a vendor.

**Gap:** the architecture is single machine and single file. It would not
survive a real organization's availability or concurrency needs, and I have
not designed for that.

## Secure development

**Standing: addressed, with tests as the evidence.** Parameterized queries
everywhere, scrypt password hashing, role checks in the service layer, and
input validation are all covered by automated tests, including the denial
cases and an injection attempt stored as inert data. The test suite runs 23
tests and passes cleanly.

**Gap:** I have no separate code review on this project, no static analysis
pipeline, and no dependency scanning, mostly because there are no
dependencies to scan. A production system would need all three.

## Vulnerability handling

**Standing: partially addressed.** Findings are a first class record type in
the register, with severity, owner, source, and status, so the system can
track its own issues the same way it tracks anyone else's. The honest gaps
in this document are recorded here rather than hidden.

**Gap:** there is no intake process, no disclosure policy, and no patching
cadence defined for this codebase. If someone found a flaw in the access
control tomorrow, the response would be me fixing it, with no formal
process around it.

## Monitoring

**Standing: partially addressed.** The append-only audit log records logins,
failures, changes, and denials, and the seeded controls include a weekly log
review. Denials are visible instead of silent, which is the part most small
tools skip.

**Gap:** monitoring here means a human reading a log. There is no alerting,
no SIEM forwarding, and no anomaly detection. A failed login at 3 a.m.
waits for the weekly review unless someone goes looking.

## Incident response readiness

**Standing: weak, and I know it.** The audit log would help reconstruct what
happened after an incident, which is a real contribution. That is where it
ends.

**Gap:** there is no incident response plan for this system, no backup and
restore routine that I have tested, and no defined way to revoke all access
quickly. If the database file were copied, my response would be improvised.
For a portfolio project that is an acceptable place to stop, but I would
not run a real register on it without fixing this section first.

## Leadership risk sign-off

**Standing: this document is the substitute, and it is not the same thing.**
The post argued that if a team builds its own GRC system, leadership should
understand and sign off on the risk. This project has no leadership and no
organization behind it. What I can do is write the risks down plainly, which
is what this file and the threat model are for.

**Gap:** nobody with authority over a real organization has accepted these
risks, because there is no real organization. Nobody should read this
project as approval to run a production GRC register this way.

## Summary of the honest limits

This is a portfolio scale system built by one person to show deliberate
security decisions. It is not a commercial GRC platform. It has no SSO or
SAML, no MFA, no encryption of the database file itself, no alerting, and no
tested backup story. The operating system and file permissions protect the
database at rest, and I rely on that rather than claiming otherwise. What it
does have is a small, tested set of controls I chose on purpose and can
defend line by line, which is the standard the post was asking for.
