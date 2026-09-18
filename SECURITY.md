# Security Policy

OpenTLV parses Tag-Length-Value data that may come from untrusted sources
(binary protocol messages, card/device data, files). Vulnerability classes of
particular interest include out-of-bounds reads or writes, integer overflows,
malformed or non-canonical length handling, excessive resource consumption or
denial-of-service conditions, parser state corruption, undefined behavior, and
other memory-safety issues.

## Supported versions

OpenTLV is pre-1.0 (currently `0.x`) and does not yet maintain parallel
maintenance branches. Security fixes are applied to the latest release on the
`main` branch; only the most recent `0.x.y` release receives security updates.
Once 1.0.0 ships, this section will be updated to describe the supported
major/minor lines.

| Version | Supported |
| --- | --- |
| Latest `0.x.y` release | :white_check_mark: |
| Older `0.x.y` releases | :x: |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.** Publicly disclosing an unresolved
vulnerability puts users of OpenTLV at risk before a fix is available.

Instead, use
[GitHub Private Vulnerability Reporting](https://github.com/marekcingel/OpenTLV/security/advisories/new)
for this repository (Security tab -> Report a vulnerability). If private
reporting is unavailable to you, contact the maintainer through the profile
contact information at <https://github.com/marekcingel> and mark the report as
security-sensitive.

### What to include

To help us triage and fix the issue quickly, include as much of the following
as you can:

- Affected OpenTLV version (tag, commit hash, or release).
- Affected component (for example a specific format, codec, profile, or CLI
  tool).
- A description of the vulnerability.
- Reproduction steps or a proof-of-concept input/program.
- The potential impact (for example crash, memory disclosure, or memory
  corruption).
- A suggested mitigation or fix, if you have one.

### What to expect

After submitting a report, you can expect:

1. **Acknowledgement** of the report, typically within a few business days.
2. **Investigation** to confirm and assess the reported issue.
3. **Fix development** on a private branch or advisory, without public
   disclosure of details until a fix is available.
4. **Coordinated disclosure** with the reporter on timing and credit.
5. A **security release and GitHub Security Advisory**, where appropriate,
   once a fix is available.

Thank you for helping keep OpenTLV and its users safe.
