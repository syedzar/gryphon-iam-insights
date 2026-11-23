# Gryphon IAM Insights

![tests](https://github.com/syedzar/gryphon-iam-insights/actions/workflows/tests.yml/badge.svg)

A small identity and access management (IAM) reporting tool built on **synthetic university data** in the **Microsoft Graph API's JSON format**. It can also call the real Graph API with your own token.

> Learning project. All data is fake (domain `mock.uoguelph.example`). No real users or tenant access.

## Features

- **Authentication methods dashboard:** MFA coverage, passwordless rate, and each user's strongest method (passkey → Authenticator → OTP → SMS → none).
- **SMS migration list:** users still relying on SMS/voice, admins first.
- **Risky sign-in report:** conditional-access-style rules for foreign single-factor sign-ins, brute force, impossible travel, and graduated accounts still signing in.
- **Graduate account cleanup (dry run):** plans the `PATCH /users/{id}` requests and writes an audit log. It never applies changes.
- **Real Graph mode:** `GET /me` and `/me/authentication/methods` with paging, 429 retry, and friendly 401/403 handling.

## Quick start

```bash
python -m venv .venv && .venv\Scripts\activate     # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt

python -m iam_insights.cli report            # all reports in the terminal
python -m iam_insights.cli cleanup --dry-run # graduate cleanup preview
streamlit run app/dashboard.py               # dashboard
pytest -q                                    # tests
```

To use real Graph data, copy `.env.example` to `.env`, set `DATA_SOURCE=graph`, and paste a token from [Graph Explorer](https://developer.microsoft.com/graph/graph-explorer). Tenant-wide reports need admin permissions, so they fall back to mock data.

## Results (mock data)

```
Users: 200 | MFA coverage: 95.0% | Passwordless-capable: 24.0%
SMS-default users to migrate: 40 (1 admins)
Risky sign-in findings: 21 (high: 15, medium: 6)
Graduated accounts still enabled past 30-day grace: 8
```

65 tests, 98% coverage, run on every push with GitHub Actions.

## Stack

Python, requests, pandas, Streamlit, Plotly, pytest, Faker.
