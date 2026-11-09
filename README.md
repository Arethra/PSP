# Physical Security Portal

Run the entire folder as a Flask application; opening the HTML files directly does not authenticate users.

## Windows PowerShell / VS Code

```powershell
cd psp
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:SECRET_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
python app.py --add-user admin@gbb.gov.ng --group "Admin"
python app.py --add-user security@gbb.gov.ng --group "Physical Security"
python app.py --add-user reception@gbb.gov.ng --group "Reception"
python app.py --add-user staff@gbb.gov.ng --group "Staff"
python app.py
```

Each account command prompts privately for its password. Open http://127.0.0.1:5000. To add more staff accounts, run the same command with another email. Store SECRET_KEY as a stable environment variable for deployments; changing it signs everyone out.

## Access

| Group | Pending requests | On site | Reports | ICMS |
|---|---|---|---|---|
| Admin | All; approval/rejection | All; check in/out | Yes | All |
| Physical Security | Hidden, matching original VMS | All; check in/out | Yes | All |
| Reception | Hidden | All; view only, matching original VMS | No | No |
| Staff | Own requests only | Own requested visitors only | No | No |

Permissions are shared by the dashboard and server routes. Staff headings open the Staff Log filtered to pending or checked-in visitors. Records are assigned to the submitting account using its exact authenticated email. Client-supplied email and group headers never grant access. Requests transition from pending to approved/rejected, then checked in and checked out. ID-card capture, collection and expiry headings open the corresponding ICMS section.

## Data and deployment

The supplied interfaces are adapted and retain their existing workflows. SQLite persists users, visitors, ICMS import batches and history in psp.sqlite3. No default passwords or sample records are installed. This is a standalone integrated application: it does not automatically import your existing PostgreSQL VMS data, browser-local ICMS records, or Active Directory groups. A database migration and directory integration are needed to connect those existing systems.

One same-origin, HttpOnly session covers all three interfaces. Logout invalidates the session for subsequent requests in every app. CSRF checks protect writes; passwords are hashed; repeated failed logins are limited. ICMS writes use version checks to prevent overwriting another user's changes; its inherited synchronous editing flow is retained. Browser scripts from the original apps may require internet access.

For server deployment, install requirements, set a stable SECRET_KEY, set HTTPS=1 behind an HTTPS reverse proxy, and run `waitress-serve --listen=127.0.0.1:5000 app:app`. Back up psp.sqlite3. Review the inherited app workflows and rendering before production rollout. This package implements local account groups; it does not claim an AD or cross-domain SSO integration.

## Reports and submitted-ID transfers

The PSP **Generate reports** action opens a VMS / ICMS chooser. Both applications show a pie chart and bar chart before the full report table, using exactly the same filtered records. These report charts work without a chart CDN. VMS keeps its existing visitor date/time filters. ICMS supports card-status and import-date filters and CSV export.

Excel imports now require **Name, End Date, Status**. Status is stored as the **Holder Status** (for example, permanent staff, contract staff or intern); the separate card workflow starts at Awaiting Capture. Optional columns remain Employee ID, Department and Course of Study. Existing Position values remain readable in old records.

On the Submitted IDs table, **Transfer** emails the holder's details, including the date of submission, to the designated server-configured recipients. The app displays those recipients before sending. Only Admin and Physical Security can transfer. The server reads the authoritative saved record, sends via encrypted SMTP, and records successful SMTP acceptance in ICMS history. No test sends real email.

Set these variables in the same PowerShell session before starting the server (replace the examples with your actual mail settings):

```powershell
$env:TRANSFER_RECIPIENTS = "hr@your-organisation.com,security@your-organisation.com"
$env:SMTP_HOST = "your-mail-server"
$env:SMTP_PORT = "587"
$env:SMTP_SECURITY = "starttls" # use "ssl" with port 465 if your provider requires it
$env:SMTP_FROM = "portal@your-organisation.com"
$env:SMTP_USERNAME = "your-mail-account"
$env:SMTP_PASSWORD = "your-mail-app-password"
```

Keep mail credentials out of source files. Configure SMTP authentication according to your provider. Until mail settings and recipients are supplied, Transfer reports a configuration error and does not claim the email was sent. SMTP acceptance does not guarantee inbox delivery; check your provider's delivery logs when needed.

Run backend tests with `python -m unittest discover -s tests -v` from the psp folder. The script-syntax check requires Node.js.


## VMS approval codes, group attendance and notifications

Visitor requests retain a shared group ID. Approval assigns one code to the entire request using the first two letters of the purpose, approval date (`DDMMYY`) and the monthly approved-visitor sequence. A group code includes the first and last visitor sequence numbers (for example, `Me-111126-0001-0010`). The code is saved on each visitor record and shown after approval. Approval email is sent to the authenticated staff account that submitted the request.

The approved-request screen lets Security select any subset of a visitor group. Selected visitors can share one tag number or be checked in individually with separate tags. Visitors not selected remain approved and can be checked in later. The sign-out modal includes an optional comment. Pending Approvals includes a `...` request-details action, and the request form accepts a guest-list document (PDF, Office, CSV or TXT; up to 10 MB).

The request form stores email-notification preferences with the request. Approval-code email is mandatory; subsequent status notifications follow the requester's selected preferences. Email uses the same SMTP environment variables described below. If SMTP is not configured or the mail server does not accept the message, approval still succeeds and the UI reports that email was not confirmed. Configure SMTP before production use.

## ID-card terminology and HR access

The interface uses **HR Uploads**, **Ready for Issuance**, **Card Issuance**, **Issued**, **Card Returns**, and **Pending Card Return**. Existing saved `Collected` records remain readable and are displayed as Issued. HR can open ICMS, view its records and reports, upload new HR personnel files, confirm records marked Submitted, and flag full-time/permanent staff for card return. HR cannot change card workflow fields, delete existing records, or transfer card details. Admin and Physical Security can mark a flagged card as returned. HR files may include an optional `Email Address` column; it appears in the Personnel table. Holder Status accepts values such as permanent/full-time staff, contract staff, intern, consultant, vendor and partner.

Create an HR account with:

```powershell
python app.py --add-user hr@your-organisation.com --group HR
```

HR is an ICMS-only role and does not have access to VMS records. Back up `psp.sqlite3` and the `private_uploads/` directory before deploying this update. The new notification-preferences table is created automatically at startup; existing visitor and ID-card records are retained.
