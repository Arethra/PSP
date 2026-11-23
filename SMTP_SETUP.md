# VMS email notifications

The VMS sends email through SMTP. Configure these environment variables in the
hosting platform's environment/secrets settings (or in the local `.env` file):

- `SMTP_HOST`: SMTP server hostname supplied by your email provider.
- `SMTP_PORT`: normally `587` for STARTTLS or `465` for SSL.
- `SMTP_SECURITY`: `starttls` (recommended with port 587) or `ssl` (port 465).
- `SMTP_USERNAME`: SMTP login username.
- `SMTP_PASSWORD`: SMTP login password or provider-generated app password.
- `SMTP_FROM`: sender address permitted by the SMTP account.

`SMTP_USERNAME` and `SMTP_PASSWORD` must either both be set or both be empty.
Keep credentials out of GitHub and never use a personal mailbox password where
the provider requires an app password or SMTP-specific credential.

After setting the variables, restart/redeploy the application. Check the server
logs for `VMS email accepted by SMTP server` or the detailed exception logged
when SMTP rejects or cannot connect. The API response also includes `emailSent`
and `emailMessage`; `emailSent: true` means the SMTP server accepted the message,
not that the recipient's mailbox provider guaranteed inbox placement.

## Event messages

- Approval: submitted visitor request fields, generated approval code, approval timestamp.
- Check-in: visitor name, tag number, check-in timestamp, and devices logged.
- Check-out: visitor name, check-out timestamp, and each device's return/log-out confirmation.

The approval, check-in and check-out notifications are sent after the corresponding
database update succeeds and are not disabled by optional notification preferences.
