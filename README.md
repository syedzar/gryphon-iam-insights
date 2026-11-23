# Gryphon IAM Insights

> A small identity and access management (IAM) reporting and automation tool, built on **mock university data** in the **Microsoft Graph API's real JSON format**, with an optional switch that calls the real Graph API using your own account.

**Status:** learning project, built to practise Microsoft Graph and IAM concepts.
**Data:** 100% synthetic. No real users, no real university data, and no admin access to any real tenant.

---

## 0. Instructions for Claude Code (read first)

Build this project end to end from this README. Work in this order and commit after each step:

1. Scaffold the repo structure in section 4. Add `pyproject.toml` or `requirements.txt`, `.gitignore`, and this README.
2. Write the mock data generator (section 5). Then generate `data/mock/*.json`, and commit it so the project runs with zero setup.
3. Build the data source layer with the `mock` / `graph` switch (section 6).
4. Build the 3 analysis modules (section 7).
5. Build the CLI (section 8) and the Streamlit dashboard (section 9).
6. Write the pytest tests (section 10) and the GitHub Actions workflow (section 11).
7. Fill in section 13 "Results" with the real numbers the tool produces on the mock data.

Constraints:
- Python 3.11+. Keep dependencies small: `requests`, `pandas`, `streamlit`, `plotly`, `pytest`, `faker`, `python-dotenv`. Don't use the Graph SDK, so the plain REST calls stay visible.
- **Never hard-code a token.** Read `GRAPH_TOKEN` from the environment or a `.env` file, and put `.env` in `.gitignore`.
- Don't use any real university logo, colours, or branding. Use the domain `mock.uoguelph.example` for fake users. The `.example` top-level domain is reserved, so no real address is ever created.
- Clean, commented code a co-op student can explain line by line. Prefer clarity over cleverness.
- Every analysis function takes plain Python data (lists of dicts in Graph format), so it works the same on mock and real data.

---

## 1. Why this exists

University IAM teams run sign-in for everyone: single sign-on (SSO), multi-factor authentication (MFA), and passkeys on Microsoft Entra ID. Typical co-op work includes:

- building **dashboards with the Microsoft Graph API** (for example, which authentication methods people use),
- **reviewing identity security controls** (for example, conditional access rules), and
- **automating access processes** (for example, cleaning up accounts when students graduate).

This project practises all three on safe mock data.

## 2. Features

| # | Feature | IAM concept it practises |
|---|---|---|
| 1 | **Authentication methods dashboard:** % of users by MFA method (Authenticator, passkey, FIDO2 key, SMS, none) | MFA, passkeys, Graph reporting |
| 2 | **SMS migration list:** users whose only or default MFA method is SMS or voice | Moving users to phishing-resistant MFA |
| 3 | **Risky sign-in report:** flags sign-ins that a conditional access policy would challenge or block | Conditional access, authentication vs. authorization |
| 4 | **Graduate account cleanup (dry run):** finds graduated students whose accounts are still enabled and lists what *would* be disabled, with an audit log | Joiner / mover / leaver life cycle, least privilege |
| 5 | **Real Graph mode:** the same code calls `GET /me` and `GET /me/authentication/methods` with your own token | Microsoft Graph REST API, OAuth access tokens |

## 3. Quick start

```bash
git clone <repo-url> && cd gryphon-iam-insights
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m iam_insights.generate_mock --users 200 --seed 42   # optional: mock data is already committed
python -m iam_insights.cli report                            # print all reports to the terminal
python -m iam_insights.cli cleanup --dry-run                 # graduate cleanup preview
streamlit run app/dashboard.py                               # open the dashboard
pytest -q                                                    # run the tests
```

## 4. Repo structure

```
gryphon-iam-insights/
├── README.md
├── requirements.txt
├── .gitignore                 # .venv, __pycache__, .env, output/
├── .env.example               # DATA_SOURCE=mock  GRAPH_TOKEN=
├── data/mock/
│   ├── users.json
│   ├── userRegistrationDetails.json
│   └── signIns.json
├── iam_insights/
│   ├── __init__.py
│   ├── config.py              # reads DATA_SOURCE and GRAPH_TOKEN
│   ├── generate_mock.py       # mock data generator (section 5)
│   ├── sources.py             # MockSource and GraphSource (section 6)
│   ├── auth_methods.py        # features 1 and 2
│   ├── risky_signins.py       # feature 3
│   ├── cleanup.py             # feature 4
│   └── cli.py                 # command-line entry point
├── app/
│   └── dashboard.py           # Streamlit dashboard
├── output/                    # audit logs and CSV exports (git-ignored)
├── tests/
│   ├── conftest.py            # small hand-written fixtures
│   ├── test_auth_methods.py
│   ├── test_risky_signins.py
│   ├── test_cleanup.py
│   └── test_sources.py
└── .github/workflows/tests.yml
```

## 5. Mock data (must match Microsoft Graph's JSON shape)

Wrap every file the way Graph does: `{"@odata.context": "...", "value": [ ... ]}`. Use `faker` with a fixed `--seed`, so the data is the same on every run.

### 5.1 `users.json` (shape of `GET /users`)

```json
{
  "id": "uuid",
  "displayName": "Jordan Lee",
  "userPrincipalName": "jlee042@mock.uoguelph.example",
  "mail": "jlee042@mock.uoguelph.example",
  "accountEnabled": true,
  "employeeType": "Student",          // "Student" | "Staff" | "Faculty" | "Graduated"
  "department": "School of Engineering",
  "createdDateTime": "2023-09-01T12:00:00Z",
  "employeeLeaveDateTime": null,      // graduation date for graduates, otherwise null
  "signInActivity": { "lastSignInDateTime": "2026-11-15T14:02:11Z" }
}
```

Mix for 200 users: about 70% Student, 12% Staff, 8% Faculty, 10% Graduated. Of the graduates, make about 60% still `accountEnabled: true`. These are the accounts the cleanup should catch. Some graduates should have graduated recently (under 30 days ago) and some long ago (over 120 days).

### 5.2 `userRegistrationDetails.json` (shape of `GET /reports/authenticationMethods/userRegistrationDetails`)

```json
{
  "id": "same uuid as the user",
  "userPrincipalName": "jlee042@mock.uoguelph.example",
  "userDisplayName": "Jordan Lee",
  "isAdmin": false,
  "isMfaRegistered": true,
  "isMfaCapable": true,
  "isPasswordlessCapable": false,
  "methodsRegistered": ["microsoftAuthenticatorPush", "mobilePhone"],
  "defaultMfaMethod": "microsoftAuthenticatorPush"
}
```

Use only real Graph method names: `microsoftAuthenticatorPush`, `microsoftAuthenticatorPasswordless`, `passKeyDeviceBound`, `fido2`, `softwareOneTimePasscode`, `mobilePhone` (SMS/voice), `email`. Rough mix: 55% Authenticator, 15% passkey or FIDO2, 20% SMS as default, 5% software OTP, 5% no MFA registered. Give 2–3 users `isAdmin: true`.

### 5.3 `signIns.json` (shape of `GET /auditLogs/signIns`)

```json
{
  "id": "uuid",
  "createdDateTime": "2026-11-20T09:15:00Z",
  "userPrincipalName": "jlee042@mock.uoguelph.example",
  "appDisplayName": "Office 365 Exchange Online",
  "ipAddress": "203.0.113.25",
  "clientAppUsed": "Browser",
  "isInteractive": true,
  "location": { "city": "Guelph", "state": "Ontario", "countryOrRegion": "CA" },
  "status": { "errorCode": 0, "failureReason": "Other." },
  "authenticationRequirement": "multiFactorAuthentication",
  "conditionalAccessStatus": "success"
}
```

Generate about 3,000 sign-ins over the last 30 days. Use only documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). Mostly use Canadian locations. Plant these on purpose, so the reports have something to find:
- 10–15 sign-ins from outside Canada with `singleFactorAuthentication`,
- 2–3 users with 5 or more failed sign-ins (`errorCode` 50126, wrong password) within 10 minutes,
- 1 "impossible travel" case: the same user in Guelph and then another country less than 2 hours apart,
- a few sign-ins by **graduated** accounts that are still enabled.

## 6. Data sources (`sources.py`)

Define one interface with two implementations. Pick one with `DATA_SOURCE=mock|graph`, using `mock` by default.

```python
class DataSource(Protocol):
    def get_users(self) -> list[dict]: ...
    def get_registration_details(self) -> list[dict]: ...
    def get_sign_ins(self) -> list[dict]: ...
    def get_me(self) -> dict: ...
    def get_my_auth_methods(self) -> list[dict]: ...
```

- **`MockSource`** reads `data/mock/*.json` and returns the `value` lists. `get_me()` returns the first user.
- **`GraphSource`** uses `requests` against `https://graph.microsoft.com/v1.0` with the header `Authorization: Bearer <GRAPH_TOKEN>`.
  - It must **follow `@odata.nextLink` paging** until every page is fetched.
  - It handles **HTTP 429** (rate limits) by waiting for the `Retry-After` header, retrying up to 3 times.
  - It handles **401** (expired token) and **403** (missing permission) with a clear message, e.g. "This endpoint needs AuditLog.Read.All, an admin-only permission. Use mock mode for this report." It must not crash.
  - Only `get_me()` and `get_my_auth_methods()` are expected to work with a normal student account. The tenant-wide reports need admin permissions, so in `graph` mode they print a friendly message and fall back to mock data.

**Getting a token (manual, for the demo only):** sign in to [Microsoft Graph Explorer](https://developer.microsoft.com/graph/graph-explorer) with your own account. Run `GET https://graph.microsoft.com/v1.0/me`, open the **Access token** tab, and copy it into `.env` as `GRAPH_TOKEN=...`. Tokens expire after about an hour. If `/me/authentication/methods` returns 403, your organization hasn't granted that permission, and the tool should say so politely.

## 7. Analysis modules

### 7.1 `auth_methods.py` (features 1 and 2)
- `method_breakdown(reg_details) -> dict[str, int]`: count users by their **strongest** registered method. Order, strongest first: passkey/FIDO2 > Authenticator passwordless > Authenticator push > software OTP > SMS/voice > email > none.
- `mfa_coverage(reg_details) -> float`: % of users with `isMfaRegistered`.
- `passwordless_rate(reg_details) -> float`: % with `isPasswordlessCapable`.
- `sms_migration_list(reg_details) -> list[dict]`: users whose `defaultMfaMethod` is `mobilePhone`, or whose only method is SMS/voice. Sort admins first, because they're the highest risk.
- `admins_without_strong_mfa(reg_details) -> list[dict]`: admins without a passkey, FIDO2 key, or Authenticator.

### 7.2 `risky_signins.py` (feature 3)
Each rule returns a list of findings: `{rule, userPrincipalName, signInId, createdDateTime, detail, severity}`.
- `rule_foreign_single_factor`: country isn't `CA` and `authenticationRequirement == "singleFactorAuthentication"`. Severity: high. In plain words, the policy it mimics is "Require MFA for sign-ins from outside Canada."
- `rule_password_spray_or_brute_force`: 5 or more failed sign-ins (`errorCode != 0`) for one user within 10 minutes. Severity: high. Make the threshold and window function parameters.
- `rule_impossible_travel`: the same user in 2 different countries less than 2 hours apart. Severity: medium.
- `rule_graduated_account_active`: a successful sign-in by a user whose `employeeType == "Graduated"`. Severity: medium.
- `run_all_rules(users, sign_ins) -> list[dict]`, sorted by severity, then time.

### 7.3 `cleanup.py` (feature 4)
- `find_stale_graduates(users, grace_days=30, today=None) -> list[dict]`: `employeeType == "Graduated"`, `accountEnabled == True`, and `employeeLeaveDateTime` more than `grace_days` ago. The grace period gives graduates time to save their files. `today` is injectable, so the tests are deterministic.
- `plan_disable(users) -> list[dict]`: for each one, the action **that would be sent**, shown as the real Graph request: `PATCH /users/{id}` with body `{"accountEnabled": false}`.
- `apply_plan(plan, dry_run=True)`: **dry run is the default and the only mode in mock**. Write every planned action to `output/audit_log_<timestamp>.csv` (timestamp, UPN, action, reason, dry_run). In real `graph` mode, refuse to run without the `--confirm` flag, and print a warning that this needs `User.ReadWrite.All` admin permission. In practice, this should never run against a real tenant from this project.

## 8. CLI (`cli.py`)

Use `argparse`. Subcommands:

```
report        # prints all of section 7 as readable tables, plus a short summary at the top
report --csv  # also writes each table to output/*.csv
cleanup --dry-run [--grace-days 30]
me            # calls get_me() and get_my_auth_methods() (shows mock or real data)
```

The summary at the top of `report` should read like this, with real numbers:

```
Users: 200 | MFA coverage: 95.0% | Passwordless-capable: 15.5%
SMS-default users to migrate: 40 (2 admins)
Risky sign-in findings: 23 (high: 15, medium: 8)
Graduated accounts still enabled past 30-day grace: 9
```

## 9. Streamlit dashboard (`app/dashboard.py`)

One page with a neutral theme. Don't use any university branding.
1. **Top row of metric tiles:** users, MFA coverage %, passwordless %, SMS-default count, risky findings, stale graduate accounts.
2. **Authentication methods:** a bar chart of the strongest method per user. Use one colour, sorted.
3. **SMS migration list:** a table with a download-CSV button.
4. **Risky sign-ins:** a table with a severity filter, plus a small bar chart of findings by rule.
5. **Graduate cleanup preview:** a table of planned `PATCH` actions and a "Download audit log" button. There is no button that applies changes.
6. **Sidebar:** shows the data source (`mock` or `graph`) and the last refresh time, with a note at the bottom: "Synthetic data. Learning project."

## 10. Tests (`pytest`)

Use **small hand-written fixtures** in `conftest.py` (5–10 records each) with known answers, not the big generated file.

- `test_auth_methods.py`: the strongest-method ordering is correct, coverage and passwordless percentages are correct, the SMS list catches the SMS-default user and puts the admin first, and an admin without strong MFA is flagged.
- `test_risky_signins.py`: each rule fires on its planted case, a safe Canadian MFA sign-in creates **no** finding, the brute-force rule respects its threshold and window (4 failures don't fire, 5 do), and impossible travel ignores 2 countries 5 hours apart.
- `test_cleanup.py`: a graduate 10 days ago (inside the grace period) is **not** flagged, one 45 days ago is flagged, a disabled graduate is ignored, the plan builds the correct `PATCH` body, a dry run writes an audit CSV with the right columns, and real-mode apply without `--confirm` refuses.
- `test_sources.py`: `MockSource` loads every file. `GraphSource` follows `@odata.nextLink` across 2 fake pages, retries on 429 using `Retry-After`, and turns 403 into a friendly error. Mock `requests` with `unittest.mock` or `responses`, so there are **no real network calls in tests**.
- A **shape test** checks that every mock record has the required Graph keys from section 5.

Target: 40 or more tests, all passing, with high coverage of `iam_insights/`. Report the real numbers in section 13.

## 11. CI (`.github/workflows/tests.yml`)

On every push and pull request: Ubuntu, Python 3.11, `pip install -r requirements.txt`, then `pytest -q --cov=iam_insights`. No secrets are needed, because CI always runs in `mock` mode.

## 12. Concepts explained (for the interview)

- **Authentication vs. authorization:** authentication proves *who you are*. Authorization decides *what you can do*. The risky sign-in rules look at authentication, and the cleanup protects authorization by removing access people no longer need.
- **Why passkeys beat SMS:** SMS codes can be intercepted or phished. A passkey's private key never leaves the device and only works on the real site.
- **Conditional access:** if-then rules applied at sign-in. Rule 7.2 #1 mimics "require MFA outside Canada."
- **Joiner / mover / leaver:** accounts are created, changed, and removed over a person's life cycle. The cleanup is the "leaver" step, with a grace period and an audit trail.
- **Least privilege:** the tool only needs read access for reports. Writing (disabling accounts) is separated, off by default, and logged.
- **Microsoft Graph:** one REST API for Microsoft 365 and Entra ID data. Send an HTTPS request with a bearer token, get JSON back, and follow `@odata.nextLink` for more pages.

## 13. Results

_Claude Code: fill this in with the real output of `python -m iam_insights.cli report` and `pytest` after the build._

- Mock users: …
- MFA coverage: … | Passwordless-capable: …
- SMS-default users: …
- Risky findings: … (by rule: …)
- Stale graduate accounts: …
- Tests: … passing, …% coverage

## 14. Limitations and next steps

- All tenant-wide data is synthetic. Real reports need admin permissions (`AuditLog.Read.All`, `UserAuthenticationMethod.Read.All`, `Reports.Read.All`) that a student account doesn't have.
- Next steps: an app registration with client-credentials auth for scheduled runs, a PowerShell version of the cleanup using the Microsoft Graph PowerShell module, and a Power BI report on the exported CSVs.

## 15. 60-second interview pitch

"After applying, I wanted to learn Microsoft Graph, so I built Gryphon IAM Insights. It's a Python tool on mock university data in Graph's real JSON format. It builds an authentication-methods dashboard and lists users still on SMS to move to passkeys. It flags sign-ins a conditional access policy would challenge, like single-factor logins from outside Canada. And it does a dry-run cleanup of graduated accounts with an audit log. The same code can call the real Graph API. I tested it with my own account on `/me`. It has [N] pytest tests running in GitHub Actions. The data is synthetic, but it taught me how Graph paging, tokens, and permissions actually work."
