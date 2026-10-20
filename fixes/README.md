# Fixes attached to Laboratory Work No. 1

## CVE-2024-56201 — Jinja2 sandbox breakout through malicious filenames

The vulnerability is in the Jinja2 compiler (3.0.0 - 3.1.4), not in the test
service, so the remediation is the dependency upgrade rather than a code change:

```
Jinja2==3.1.4   ->   Jinja2==3.1.5
```

`requirements.txt` in this folder is the corrected pin. It is otherwise
identical to `cve-2024-56201-lab/requirements.txt`, which pins the vulnerable
version on purpose so that the attack can be reproduced.

Why this is effective: 3.1.5 escapes `{` and `}` in the template position
before it is formatted into the generated error message (commit `767b236`,
issue 1792). The template name therefore stays a literal string and is never
parsed as an f-string expression, which removes the code channel entirely.
Application-level filtering of names would be a filter, not a boundary, and
would not survive the next encoding.

Verification: after the upgrade the same two requests return the template name
as text (`{7+7}.html` instead of `14.html`, no `uid=...`) and the legitimate
`hello.html` request still answers 200. See Section 9 and Section 10 of the
report, and Figures 12-14.

## Flask API (Laboratory Work No. 1, first part)

The API needed no remediation file of its own; the security controls are part
of `app.py` (parameterised statements, output escaping, bcrypt, JWT
verification). The earlier Flask template-injection exercise is superseded by
the CVE work above.
