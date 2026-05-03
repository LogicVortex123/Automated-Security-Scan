# Automated Security Assessment Dashboard for LibreHealth EHR Workflows

A small full-stack demo that simulates security scans for common LibreHealth EHR workflows. The backend is plain PHP (no framework). **MySQL is optional:** if MySQL is missing or not configured, the app automatically uses **SQLite** at `backend/data/security_scans.sqlite`. HTML reports use XSLT when `ext-xsl` is available, otherwise a built-in HTML template.

## Prerequisites

- PHP 8.0+ with **json** (always). **PDO is optional:** if `pdo_sqlite` / `pdo_mysql` are disabled, scans are stored in **`backend/data/scans.json`** automatically. Optional: **dom** + **xsl** for XSLT reports (otherwise a built-in HTML template is used).

## Database setup

**Easiest (no MySQL):** run the app as below; the first API call creates `backend/data/security_scans.sqlite` automatically.

**Optional MySQL:** start MySQL, then from the project root:

```bash
mysql -u root -p < database/schema.sql
```

If credentials differ, set `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASS`, or edit `backend/config.php`. To **force SQLite only** (skip trying MySQL), set environment variable `DB_SQLITE_ONLY=1`.

**Check connectivity:** open [http://localhost:8000/health](http://localhost:8000/health) — you should see `"ok":true` and `db_driver` of `sqlite` or `mysql`.

## Run the application

From the **project root** (the folder that contains `router.php`):

```bash
php -S localhost:8000 router.php
```

Open **http://localhost:8000** in a browser.

**Windows:** double-click **`start-server.bat`** in the project folder (starts PHP and opens the browser).

**Live Server / wrong port:** the dashboard has a **Connection help** section where you paste your PHP server URL (e.g. `http://127.0.0.1:8000`) and click **Save & reconnect**. The API sends CORS headers for local development.

**MongoDB is not used** — only SQLite (default) or optional MySQL.

### Frontend dashboard

- **Module selector** + **Run Scan** calls `POST /security-check` and refreshes cards, posture, and trend.
- On load and when you change modules, the UI pulls `GET /report/{module}` and shows the **latest stored scan** (if any) plus a **trend** of the last five runs.
- **Download HTML Report** fetches `GET /report-export/{module}` and saves an `.html` file (XSLT if enabled, otherwise built-in HTML). Use the browser’s print dialog on that file for PDF.
- **Print view** opens the system print dialog for the current dashboard (print CSS hides controls).

### API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | JSON status and active DB driver (`sqlite` or `mysql`). |
| `POST` | `/security-check` | Body: `{"module":"Patient Registration"}`. Returns `{ module, vulnerabilities: [...] }` and stores the run (SQLite or MySQL). |
| `GET` | `/report/{module}` | Historical scans for `module` (URL-encoded), newest first. |
| `GET` | `/report-export/{module}` | Downloadable HTML report for the **latest** stored scan. |

Example:

```bash
curl -X POST http://localhost:8000/security-check ^
  -H "Content-Type: application/json" ^
  -d "{\"module\":\"Billing\"}"
```

## Project layout

- `router.php` — routes API calls and serves `frontend/` assets for the built-in server
- `backend/` — configuration, PDO helper, scanner logic, XSLT helper, API scripts
- `backend/xsl/report.xsl` — transforms scan XML into printable HTML
- `database/schema.sql` — MySQL schema
- `frontend/` — dashboard (HTML/CSS/JS)

## CVSS methodology (simplified)

This project does **not** compute live CVSS vectors. Each simulated finding uses a **fixed CVSS v3.1-style base score** chosen to reflect typical impact for that issue class in a web EHR context (confidentiality, integrity, availability assumptions are implicit in the chosen number).

**Severity bands** (from numeric score):

- **Critical**: 9.0–10.0  
- **High**: 7.0–8.9  
- **Medium**: 4.0–6.9  
- **Low**: 0.1–3.9  

The **module overall score** shown in the UI and stored in the database is the **maximum CVSS** among findings for that scan (worst-case posture for the workflow).

Official CVSS v3.1 defines base, temporal, and environmental metrics; full calculators use vectors such as `CVSS:3.1/AV:N/AC:L/...`. This demo uses **base scores only**, as constants, to keep the stack simple and deterministic.

## Printable PDF

Use the browser’s **Print → Save as PDF** on the downloaded HTML report.

## Healthcare modules (mock data)

The scanner recognizes four modules with predefined finding sets:

- Patient Registration  
- Lab Results  
- Billing  
- Appointment Scheduling  

Finding types covered across modules include: SQL Injection, XSS, CSRF, Weak Authentication, and Data Exposure.

## Troubleshooting

- **Database error on scan**: confirm MySQL is running, schema is loaded, and credentials in `backend/config.php` match your server.
- **`Unexpected end of JSON input` in the browser**: you are not talking to `router.php` (wrong URL, static server only, or empty PHP crash). Use `php -S localhost:8000 router.php` from the project root and open `http://localhost:8000/`.
- **Report download / XSL**: optional; without `ext-xsl` the app still downloads HTML via the built-in template.
- **`could not find driver`**: the app now falls back to **`backend/data/scans.json`** (no PDO needed). To use SQLite/MySQL instead, enable `pdo_sqlite` / `pdo_mysql` in `php.ini`.

## License

Demonstration code for local learning and prototyping.
