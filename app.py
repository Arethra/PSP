import os, json, sqlite3, secrets, argparse, smtplib, ssl, re, io
from urllib.parse import quote
import requests
from postgrest.exceptions import APIError
from supabase import create_client
from datetime import datetime, timedelta
from flask import Flask, request, session, jsonify, redirect, render_template, abort, g
from werkzeug.security import generate_password_hash, check_password_hash
""" from dotenv import load_dotenv

load_dotenv() """


app = Flask(__name__)
key = os.environ.get('SECRET_KEY')
if not key:
 raise RuntimeError('Set SECRET_KEY to a long random value before starting.')

app.config.update(SECRET_KEY=key, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
                  SESSION_COOKIE_SECURE=os.environ.get('HTTPS') == '1',
                  PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
                  MAX_CONTENT_LENGTH=10 * 1024 * 1024)

SUPABASE_URL = os.environ.get('SUPABASE_URL', '').rstrip('/')
SUPABASE_KEY = os.environ.get('SUPABASE_SERVICE_ROLE_KEY')
if not SUPABASE_URL or not SUPABASE_KEY:
 raise RuntimeError('Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.')

GROUPS = ['Admin', 'Physical Security', 'Reception', 'Staff', 'HR']

# All database access goes over HTTPS (PostgREST), so no direct/IPv6 Postgres connection is needed.
sb = create_client(SUPABASE_URL, SUPABASE_KEY)
PAGE = 1000


def fetch_all(name, cols='*', order=None, **eq):
 """Fetch every row (PostgREST caps a single response at 1000 rows)."""
 out = []; start = 0
 while True:
  q = sb.table(name).select(cols)
  for k, val in eq.items(): q = q.eq(k, val)
  if order: q = q.order(order)
  chunk = q.range(start, start + PAGE - 1).execute().data
  out += chunk
  if len(chunk) < PAGE: return out
  start += PAGE


def fetch_one(name, **eq):
 q = sb.table(name).select('*')
 for k, val in eq.items(): q = q.eq(k, val)
 data = q.limit(1).execute().data
 return data[0] if data else None


def all_visitors(owner=None):
 rows_ = fetch_all('visitors', 'id,owner,data', order='id', **({'owner': owner} if owner else {}))
 return [{'id': r['id'], 'owner': r['owner'], 'item': json.loads(r['data'])} for r in rows_]


def get_icms():
 r = fetch_one('icms', id=1)
 if not r:
  sb.table('icms').upsert({'id': 1, 'data': json.dumps({'batches': [], 'history': []}), 'version': 0},
                          on_conflict='id', ignore_duplicates=True).execute()
  r = fetch_one('icms', id=1)
 return r



def extract_guest_names(file_obj, ext):
 """Extract one guest name per non-empty row/line from common document formats."""
 raw = file_obj.read()
 names = []
 try:
  if ext == '.txt':
   text = raw.decode('utf-8-sig')
   names = [x.strip() for x in text.splitlines() if x.strip()]
  elif ext == '.csv':
   import csv
   rows_ = list(csv.reader(io.StringIO(raw.decode('utf-8-sig'))))
   header_names = {'name', 'full name', 'guest name', 'visitor name'}
   header = [str(x or '').strip().casefold() for x in rows_[0]] if rows_ else []
   col = next((i for i, value in enumerate(header) if value in header_names), 0)
   data_rows = rows_[1:] if header and header[col] in header_names else rows_
   names = [str(row[col]).strip() for row in data_rows if len(row) > col and str(row[col]).strip()]
  elif ext == '.xlsx':
   from openpyxl import load_workbook
   wb = load_workbook(io.BytesIO(raw), read_only=True, data_only=True)
   ws = wb.active
   rows_ = list(ws.iter_rows(values_only=True))
   header_names = {'name', 'full name', 'guest name', 'visitor name'}
   header = [str(x or '').strip().casefold() for x in rows_[0]] if rows_ else []
   col = next((i for i, value in enumerate(header) if value in header_names), 0)
   data_rows = rows_[1:] if header and header[col] in header_names else rows_
   names = [str(row[col]).strip() for row in data_rows if len(row) > col and row[col] is not None and str(row[col]).strip()]
  elif ext == '.docx':
   from docx import Document
   doc = Document(io.BytesIO(raw))
   names = [p.text.strip() for p in doc.paragraphs if p.text.strip()]
   for table in doc.tables:
    for row in table.rows:
     if row.cells and row.cells[0].text.strip(): names.append(row.cells[0].text.strip())
  elif ext == '.xls':
   import xlrd
   book = xlrd.open_workbook(file_contents=raw)
   sheet = book.sheet_by_index(0)
   header_names = {'name', 'full name', 'guest name', 'visitor name'}
   header = [str(sheet.cell_value(0, c)).strip().casefold() for c in range(sheet.ncols)] if sheet.nrows else []
   col = next((i for i, value in enumerate(header) if value in header_names), 0)
   first_data_row = 1 if header and header[col] in header_names else 0
   names = [str(sheet.cell_value(r, col)).strip() for r in range(first_data_row, sheet.nrows) if str(sheet.cell_value(r, col)).strip()]
  elif ext == '.doc':
   raise ValueError('Legacy .doc files cannot be read for automatic name extraction. Please save the document as .docx or PDF and upload it again.')
  elif ext == '.pdf':
   from pypdf import PdfReader
   reader = PdfReader(io.BytesIO(raw))
   text = '\n'.join(page.extract_text() or '' for page in reader.pages)
   names = [x.strip() for x in text.splitlines() if x.strip()]
 except ImportError as exc:
  raise ValueError(f'Document extraction dependency is missing: {exc.name}')
 except Exception as exc:
  raise ValueError('The uploaded document could not be read. Use a text-based PDF, DOCX, XLSX, CSV or TXT file.')
 # Remove common header labels and duplicate blank noise; keep names in document order.
 names = [n for n in names if n.casefold() not in ('name', 'full name', 'guest name', 'visitor name')]
 return names

def client_ip():
 # Behind Vercel, remote_addr is the proxy. Set TRUST_PROXY=1 to use the forwarded client IP.
 if os.environ.get('TRUST_PROXY') == '1':
  fwd = request.headers.get('X-Forwarded-For', '')
  if fwd: return fwd.split(',')[0].strip()
 return request.remote_addr or 'unknown'


def format_mail_datetime(value):
 """Format stored ISO timestamps for human-readable email notifications."""
 if not value:
  value = datetime.now().astimezone().isoformat()
 try:
  parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
  return parsed.astimezone().strftime('%d %B %Y, %I:%M %p')
 except (TypeError, ValueError):
  return str(value)


def send_mail(to, subject, body):
 """Send a VMS notification as a readable HTML email with a plain-text fallback."""
 host = (os.environ.get('SMTP_HOST') or '').strip()
 sender = (os.environ.get('SMTP_FROM') or '').strip()
 if not to:
  app.logger.error('VMS email not sent: recipient address is missing.')
  return False
 if not host or not sender:
  app.logger.error('VMS email not sent: SMTP_HOST and SMTP_FROM must be configured in the deployment environment.')
  return False
 from email.message import EmailMessage
 from html import escape
 msg = EmailMessage()
 msg['From'] = sender
 msg['To'] = to
 msg['Subject'] = subject
 msg.set_content(body)
 rows = []
 paragraphs = []
 for line in body.splitlines():
  line = line.strip()
  if not line:
   continue
  if ':' in line:
   label, value = line.split(':', 1)
   rows.append(f'<tr><th style="text-align:left;padding:11px 14px;color:#52605a;background:#f5f8f6;border-bottom:1px solid #e5ebe7;width:38%;">{escape(label.strip())}</th><td style="padding:11px 14px;border-bottom:1px solid #e5ebe7;color:#17211c;">{escape(value.strip())}</td></tr>')
  else:
   paragraphs.append(f'<p style="margin:0 0 14px;color:#26332c;line-height:1.6;">{escape(line)}</p>')
 html = ('<!doctype html><html><body style="margin:0;padding:28px 12px;background:#f3f6f4;font-family:Arial,Helvetica,sans-serif;color:#17211c;">'
  '<div style="max-width:620px;margin:0 auto;background:#fff;border:1px solid #e1e8e3;border-radius:12px;overflow:hidden;">'
  f'<div style="padding:22px 26px;background:#174d36;color:#fff;"><div style="font-size:12px;letter-spacing:1px;text-transform:uppercase;opacity:.85;">Physical Security Portal</div><h2 style="margin:8px 0 0;font-size:21px;">{escape(subject)}</h2></div>'
  f'<div style="padding:25px 26px;">{"".join(paragraphs)}'
  + (('<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;margin:16px 0;">' + ''.join(rows) + '</table>') if rows else '')
  + '<p style="margin:22px 0 0;color:#718078;font-size:12px;">This is an automated notification from the Physical Security Portal.</p></div></div></body></html>')
 msg.add_alternative(html, subtype='html')
 try:
  mode = (os.environ.get('SMTP_SECURITY') or 'starttls').strip().lower()
  if mode not in ('starttls', 'ssl'):
   raise ValueError('SMTP_SECURITY must be either starttls or ssl.')
  port = int(os.environ.get('SMTP_PORT', '465' if mode == 'ssl' else '587'))
  username = (os.environ.get('SMTP_USERNAME') or '').strip()
  password = os.environ.get('SMTP_PASSWORD') or ''
  if bool(username) != bool(password):
   raise ValueError('Set both SMTP_USERNAME and SMTP_PASSWORD, or leave both empty.')
  conn = (smtplib.SMTP_SSL(host, port, timeout=20, context=ssl.create_default_context()) if mode == 'ssl' else smtplib.SMTP(host, port, timeout=20))
  with conn as smtp:
   smtp.ehlo()
   if mode == 'starttls':
    smtp.starttls(context=ssl.create_default_context()); smtp.ehlo()
   if username: smtp.login(username, password)
   refused = smtp.send_message(msg)
   if refused:
    app.logger.error('VMS email refused by SMTP server for recipient(s): %s', ', '.join(refused)); return False
  app.logger.info('VMS email accepted by SMTP server: recipient=%s subject=%s', to, subject)
  return True
 except Exception:
  app.logger.exception('VMS notification email failed: recipient=%s subject=%s', to, subject)
  return False


def email_field_lines(v):
 """Build a readable copy of the submitted visitor request for approval emails."""
 fields = [('Visitor name(s)', v.get('fullName')), ('Number of guests', v.get('guestCount')), ('Phone number', v.get('phone')), ('Address / Organisation', v.get('addressOrg')), ('Whom to see', v.get('toSee')), ('Floor', v.get('floor')), ('Department', v.get('department')), ('Purpose of visit', v.get('purpose'))]
 lines = [f'{label}: {value}' for label, value in fields if value not in (None, '')]
 attachment = v.get('guestAttachment') or {}
 if attachment.get('filename'): lines.append(f'Guest list document: {attachment["filename"]}')
 return '\n'.join(lines)


def visitor_devices(v):
 """Return the devices recorded for this visitor at check-in."""
 items = []
 if v.get('laptop'):
  label = 'Laptop'
  if v.get('laptopQuantity'):
   label += f' x{v["laptopQuantity"]}'
  if v.get('laptopModel'):
   label += f' ({v["laptopModel"]})'
  if v.get('laptopDetail'):
   label += f' — {v["laptopDetail"]}'
  items.append(label)
 if v.get('otherDevice'):
  items.append(str(v.get('otherDeviceDetails') or 'Other device'))
 return ', '.join(items) if items else 'No devices logged'


def group_code(v, now, visitors):
 """Return (approval code, metadata to store on every member of the group)."""
 group = v.get('groupId') or v['id']
 for x in visitors:
  i = x['item']
  if i.get('groupId') == group and i.get('approvalCode') is not None:
   return i['approvalCode'], {}
 month = now.strftime('%m%y')
 # The sequence is the visitor's position in the monthly approved register.
 start = sum(1 for x in visitors
             if x['item'].get('approvalMonth') == month
             and x['item'].get('status') in ('approved', 'checked_in', 'checked_out')
             and x['item'].get('approvalSequence') is not None) + 1
 count = max(1, sum(1 for x in visitors if x['item'].get('groupId') == group))
 end = start + count - 1
 # Department prefix: first 3 letters of the requester's department (e.g. Finance -> FIN).
 dept = re.sub('[^A-Za-z]', '', str(v.get('department') or 'GEN'))[:3].upper().ljust(3, 'X')
 code = f"{dept}-{now.strftime('%d%m%y')}-{start:04d}" + (f"-{end:04d}" if count > 1 else '')
 return code, dict(approvalMonth=month, approvalSequence=start, approvedGroupCount=count)


def notify_requester(v, subject, body, status_change=True):
 email = v.get('requestEmail')
 if not email: return
 pref = fetch_one('notification_preferences', email=email)
 every = v.get('notifyEveryAction') if 'notifyEveryAction' in v else (bool(pref['every_action']) if pref else False)
 status = v.get('notifyStatusChange') if 'notifyStatusChange' in v else (bool(pref['status_changes']) if pref else True)
 if every or (status_change and status): send_mail(email, subject, body)


def user():
 if hasattr(g, 'u'): return g.u
 email = session.get('email')
 r = fetch_one('users', email=email) if email else None
 g.u = dict(email=r['email'], group=r['group_name']) if r else None
 return g.u


@app.before_request
def protect():
 if 'csrf' not in session: session['csrf'] = secrets.token_hex(32)
 if request.method not in ('GET', 'HEAD', 'OPTIONS') and not secrets.compare_digest(request.headers.get('X-CSRF-Token', request.form.get('csrf', '')), session['csrf']): abort(403)
 if request.path not in ('/', '/login') and not request.path.startswith('/static/') and not user():
  if request.path.startswith('/api/'): abort(401)
  return redirect('/login')


@app.errorhandler(403)
@app.errorhandler(401)
@app.errorhandler(409)
@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(502)
@app.errorhandler(503)
def error(e): return jsonify(message=e.description), e.code


@app.errorhandler(APIError)
def database_error(e):
 app.logger.exception('Supabase request failed')
 return jsonify(message='The database request failed. Check Supabase configuration and tables.'), 503


@app.context_processor
def context(): return {'user': user(), 'csrf': session['csrf']}


def require(*groups):
 if not user() or user()['group'] not in groups: abort(403)


def rows():
 owner = user()['email'] if user()['group'] in ('Staff', 'HR') else None
 return [x['item'] for x in all_visitors(owner)]


@app.route('/')
def home(): return redirect('/dashboard' if user() else '/login')


@app.route('/login', methods=['GET', 'POST'])
def login():
 if request.method == 'GET': return render_template('login.html', error=None)
 email = request.form.get('email', '').strip().lower(); password = request.form.get('password', ''); now = datetime.now().timestamp()
 ip = client_ip()
 sb.table('attempts').delete().lt('t', now - 900).execute()
 count = sb.table('attempts').select('ip', count='exact').eq('ip', ip).execute().count or 0
 if count >= 10: return render_template('login.html', error='Too many attempts. Try again in 15 minutes.'), 429
 r = fetch_one('users', email=email)
 if not r or not check_password_hash(r['password'], password):
  sb.table('attempts').insert({'ip': ip, 't': now}).execute()
  return render_template('login.html', error='Invalid email or password.'), 401
 session.clear(); session['email'] = email; session['csrf'] = secrets.token_hex(32); session.permanent = True
 return redirect('/dashboard')


@app.post('/logout')
def logout(): session.clear(); return redirect('/login')


@app.get('/dashboard')
def dashboard():
 gr = user()['group']; v = rows(); tiles = []
 if gr in ('Admin', 'Physical Security'): tiles.append(('Generate reports', 'VMS / ICMS', '#report-chooser', 'Choose an application'))
 if gr in ('Admin', 'Staff'): tiles.append(('My pending requests' if gr == 'Staff' else 'Pending requests', 'VMS', '/vms?section=' + ('staff-log&status=pending' if gr == 'Staff' else 'approvals'), sum(x.get('status') == 'pending' for x in v)))
 if gr != 'HR': tiles.append(('My visitors on site' if gr == 'Staff' else 'Visitors on site', 'VMS', '/vms?section=' + ('staff-log&status=checked_in' if gr == 'Staff' else 'onsite'), sum(x.get('status') == 'checked_in' for x in v)))
 if gr in ('Admin', 'Physical Security', 'HR'):
  data = json.loads(get_icms()['data'])
  counts = {'Awaiting Capture': 0, 'Pending': 0, 'Expired': 0}
  for b in data['batches']:
   for r in b.get('records', []):
    s = r.get('status', 'Awaiting Capture')
    try:
     if s != 'Submitted' and datetime.fromisoformat(r.get('endDate', '')[:10]).date() < datetime.now().date(): s = 'Expired'
    except (ValueError, TypeError): pass
    if s in counts: counts[s] += 1
  for title, status, section in [('ID cards to capture', 'Awaiting Capture', 'capture'), ('ID cards ready for issuance', 'Pending', 'collection'), ('Expired IDs', 'Expired', 'expired')]: tiles.append((title, 'ICMS', '/icms?section=' + section, counts[status]))
  return_count = sum(1 for b in data['batches'] for r in b.get('records', []) if r.get('returnRequired') and r.get('returnStatus') != 'Returned')
  tiles.append(('ID cards pending return', 'ICMS', '/icms?section=cardreturn', return_count))
 return render_template('dashboard.html', tiles=tiles)


@app.get('/vms')
def vms():
 require('Admin', 'Physical Security', 'Reception', 'Staff')
 return render_template('vms.html')


@app.route('/api/vms/notification-preferences', methods=['GET', 'PUT'])
def vms_notification_preferences():
 require('Admin', 'Physical Security', 'Staff')
 email = user()['email']
 if request.method == 'GET':
  r = fetch_one('notification_preferences', email=email)
  return jsonify(every_action=bool(r['every_action']) if r else False, status_changes=bool(r['status_changes']) if r else True)
 data = request.get_json(silent=True) or {}
 sb.table('notification_preferences').upsert({'email': email, 'every_action': int(bool(data.get('every_action'))),
                                              'status_changes': int(bool(data.get('status_changes', True)))}, on_conflict='email').execute()
 return jsonify(saved=True)


@app.get('/icms')
def icms():
 require('Admin', 'Physical Security', 'HR')
 r = get_icms()
 return render_template('ICMS.html', state=json.loads(r['data']), version=r['version'])


@app.route('/api/visitors', methods=['GET', 'POST'])
def visitors():
 if request.method == 'GET':
  require('Admin', 'Physical Security', 'Reception', 'Staff')
  return jsonify(rows())
 require('Admin', 'Physical Security', 'Staff'); v = request.get_json(silent=True)
 if not isinstance(v, dict) or not v.get('fullName'): abort(400, description='Visitor name is required.')
 v.update(id=secrets.token_hex(16), requestEmail=user()['email'], status='pending', timeIn=None, timeOut=None, approvedAt=None, approvedBy=None, tagNo='', approvalCode=None, createdAt=v.get('createdAt') or datetime.now().astimezone().isoformat())
 sb.table('visitors').insert({'id': v['id'], 'owner': user()['email'], 'data': json.dumps(v)}).execute()
 return jsonify(visitor=v), 201


@app.post('/api/visitors/attachment')
def visitor_attachment():
 require('Admin', 'Physical Security', 'Staff')
 from werkzeug.utils import secure_filename
 f = request.files.get('file')
 if not f: abort(400, description='Choose a document to upload.')
 ext = os.path.splitext(secure_filename(f.filename))[1].lower()
 if ext not in ('.pdf', '.doc', '.docx', '.xls', '.xlsx', '.csv', '.txt'): abort(400, description='Unsupported attachment type.')
 bucket = os.environ.get('SUPABASE_STORAGE_BUCKET', 'private-uploads')
 name = secrets.token_hex(16) + ext
 try:
  f.stream.seek(0)
  extracted_names = extract_guest_names(f.stream, ext)
  if not extracted_names: abort(400, description='No names could be extracted. Upload a text-based guest list with one name per line or in the first column.')
 except ValueError as exc:
  abort(400, description=str(exc))
 f.stream.seek(0)
 storage_path = f"{quote(bucket, safe='')}/{quote(name, safe='')}"
 headers = {'apikey': SUPABASE_KEY, 'Authorization': f'Bearer {SUPABASE_KEY}',
            'Content-Type': f.mimetype or 'application/octet-stream', 'x-upsert': 'false'}
 try:
  response = requests.post(f"{SUPABASE_URL}/storage/v1/object/{storage_path}",
                           headers=headers, data=f.read(), timeout=30)
  if not response.ok:
   app.logger.error('Supabase attachment upload failed: status=%s bucket=%s body=%s', response.status_code, bucket, response.text[:500])
   hint = {404: f'Storage bucket "{bucket}" was not found. Create it in Supabase Storage or set SUPABASE_STORAGE_BUCKET.',
           401: 'Supabase rejected the key. Check SUPABASE_SERVICE_ROLE_KEY.', 403: 'Supabase rejected the key. Check SUPABASE_SERVICE_ROLE_KEY.'}.get(response.status_code)
   abort(502, description=hint or f'The attachment could not be stored (Supabase returned {response.status_code}). Check the server log.')
 except requests.RequestException:
  app.logger.exception('Supabase attachment upload failed')
  abort(502, description='The attachment could not be stored. Check SUPABASE_URL and network access.')
 # Remember which files this session uploaded so only they can be removed before submission.
 session['pending_uploads'] = (session.get('pending_uploads', []) + [name])[-20:]
 return jsonify(filename=f.filename, stored=name, names=extracted_names), 201


@app.delete('/api/visitors/attachment/<filename>')
def delete_visitor_attachment(filename):
 require('Admin', 'Physical Security', 'Staff')
 safe = os.path.basename(filename)
 pending = session.get('pending_uploads', [])
 # Only a file uploaded in this session that no visitor request refers to may be deleted.
 if safe not in pending: abort(404)
 if any((x['item'].get('guestAttachment') or {}).get('stored') == safe for x in all_visitors()):
  abort(409, description='This document is attached to a submitted request and cannot be deleted.')
 bucket = os.environ.get('SUPABASE_STORAGE_BUCKET', 'private-uploads')
 storage_path = f"{quote(bucket, safe='')}/{quote(safe, safe='')}"
 headers = {'apikey': SUPABASE_KEY, 'Authorization': f'Bearer {SUPABASE_KEY}'}
 try:
  response = requests.delete(f"{SUPABASE_URL}/storage/v1/object/{storage_path}", headers=headers, timeout=30)
  if response.status_code != 404: response.raise_for_status()
 except requests.RequestException:
  app.logger.exception('Supabase attachment delete failed')
  abort(502, description='The attachment could not be deleted from storage.')
 session['pending_uploads'] = [x for x in pending if x != safe]
 return jsonify(deleted=True)


@app.get('/api/visitors/attachment/<filename>')
def download_visitor_attachment(filename):
 from flask import send_file
 safe = os.path.basename(filename)
 found = [(x['owner'], x['item']) for x in all_visitors() if (x['item'].get('guestAttachment') or {}).get('stored') == safe]
 if not found: abort(404)
 if user()['group'] not in ('Admin', 'Physical Security') and not any(owner == user()['email'] for owner, item in found): abort(403)
 bucket = os.environ.get('SUPABASE_STORAGE_BUCKET', 'private-uploads')
 storage_path = f"{quote(bucket, safe='')}/{quote(safe, safe='')}"
 headers = {'apikey': SUPABASE_KEY, 'Authorization': f'Bearer {SUPABASE_KEY}'}
 try:
  response = requests.get(f"{SUPABASE_URL}/storage/v1/object/{storage_path}", headers=headers, timeout=30)
  response.raise_for_status()
 except requests.RequestException:
  app.logger.exception('Supabase attachment download failed')
  abort(502, description='The attachment could not be retrieved from storage.')
 download_name = (found[0][1].get('guestAttachment') or {}).get('filename', safe)
 return send_file(io.BytesIO(response.content), as_attachment=True, download_name=download_name)


@app.route('/api/visitors/<id>', methods=['PATCH'])
@app.route('/api/visitors/<id>/<action>', methods=['PATCH'])
def change(id, action=None):
 data = request.get_json(silent=True) or {}
 if action in ('check-in', 'check-out'): require('Admin', 'Physical Security')
 else: require('Admin')
 r = fetch_one('visitors', id=id)
 if not r: abort(404)
 raw = r['data']; rev = r.get('rev') or 0  # rev is the optimistic-lock token when saving
 v = json.loads(raw); old = v['status']; now = datetime.now().astimezone().isoformat()
 target = {'reject': 'rejected', 'check-in': 'checked_in', 'check-out': 'checked_out'}.get(action, data.get('status'))
 if (old, target) not in [('pending', 'approved'), ('pending', 'rejected'), ('approved', 'checked_in'), ('checked_in', 'checked_out')]: abort(409, description='Invalid visitor status transition.')
 email_sent = None; others = []
 if target == 'approved':
  everyone = all_visitors()
  v.update(approvedAt=now, approvedBy=user()['email'])
  code, meta = group_code(v, datetime.now().astimezone(), everyone)
  group = v.get('groupId') or v['id']
  for x in everyone:
   if x['id'] == id: continue
   item = x['item']
   if (item.get('groupId') == group or x['id'] == group) and item.get('status') == 'pending':
    item.update(meta, status='approved', approvedAt=now, approvedBy=user()['email'], approvalCode=code)
    others.append((x['id'], item))
  v.update(meta, approvalCode=code)
 if target == 'rejected': v.update(rejectedAt=now, rejectedBy=user()['email'], rejectionReason=data.get('reason', ''))
 if target == 'checked_in':
  tag = str(data.get('tagNo', ''))
  if not tag.isdigit() or not 0 <= int(tag) <= 100: abort(400, description='Choose a valid tag.')
  mine = v.get('groupId') or v.get('id')
  for x in all_visitors():
   i = x['item']
   if i.get('status') == 'checked_in' and str(i.get('tagNo')) == tag and (i.get('groupId') or i.get('id')) != mine:
    abort(409, description='Tag is already in use.')
  for k in ('tagNo', 'laptop', 'laptopQuantity', 'laptopModel', 'laptopDetail', 'laptopDetails', 'otherDevice', 'otherDeviceDetails', 'remarks'):
   if k in data: v[k] = data[k]
  v['timeIn'] = now
  v['checkedInBy'] = user()['email']
 if target == 'checked_out':
  v['timeOut'] = now
  v['checkedOutBy'] = user()['email']
  for k in ('signature', 'signOutRemarks', 'signOutComment', 'laptopReturned', 'otherDeviceReturned'):
   if k in data: v[k] = data[k]
 v['status'] = target
 saved = sb.table('visitors').update({'data': json.dumps(v), 'rev': rev + 1}).eq('id', id).eq('rev', rev).execute()
 if not saved.data: abort(409, description='This visitor was changed by someone else. Reload and try again.')
 for oid, item in others:
  sb.table('visitors').update({'data': json.dumps(item)}).eq('id', oid).execute()
 # Send event emails only after the visitor record has been saved successfully.
 # These three operational notifications are not suppressed by optional preferences.
 if target == 'approved':
  approval_body = (
   'Your visitor request has been approved.\n\n'
   f'{email_field_lines(v)}\n\n'
   f'Generated approval code: {v.get("approvalCode") or "—"}\n'
   f'Time and date: {format_mail_datetime(now)}'
  )
  email_sent = send_mail(v.get('requestEmail'), 'Visitor request approved', approval_body)
 elif target == 'checked_in':
  email_sent = send_mail(
   v.get('requestEmail'), 'Visitor checked in',
   'Your visitor has been checked in.\n\n'
   f'Visitor name: {v.get("fullName") or "—"}\n'
   f'Tag number: {v.get("tagNo") or "—"}\n'
   f'Time and date: {format_mail_datetime(v.get("timeIn") or now)}\n'
   f'Devices logged: {visitor_devices(v)}'
  )
 elif target == 'checked_out':
  returned = []
  if v.get('laptop'):
   returned.append(f'Laptop: {"logged out" if v.get("laptopReturned") else "return not confirmed"}')
  if v.get('otherDevice'):
   returned.append(f'{v.get("otherDeviceDetails") or "Other device"}: {"logged out" if v.get("otherDeviceReturned") else "return not confirmed"}')
  email_sent = send_mail(
   v.get('requestEmail'), 'Visitor checked out',
   'Your visitor has been checked out.\n\n'
   f'Visitor name: {v.get("fullName") or "—"}\n'
   f'Time and date: {format_mail_datetime(v.get("timeOut") or now)}\n'
   f'Devices logged out: {", ".join(returned) if returned else "No devices were logged at check-in"}'
  )
 elif target == 'rejected':
  email_sent = send_mail(
   v.get('requestEmail'), 'Visitor request rejected',
   f'Your visitor request was rejected.\nReason: {v.get("rejectionReason") or "Not specified"}\nTime and date: {format_mail_datetime(now)}'
  )
 return jsonify(visitor=v, emailSent=email_sent,
                emailMessage=('Email accepted by SMTP server.' if email_sent else 'Email was not sent. Check SMTP configuration and application logs.'))


@app.route('/api/icms', methods=['PUT'])
def save_icms():
 require('Admin', 'Physical Security', 'HR'); data = request.get_json(silent=True)
 if not isinstance(data, dict) or not isinstance(data.get('batches'), list) or not isinstance(data.get('history'), list): abort(400)
 version = data.get('version')
 if not isinstance(version, int) or isinstance(version, bool): abort(409, description='Another user changed ID-card records. Reload before editing.')
 current = json.loads(get_icms()['data'])
 if user()['group'] == 'HR':
  old_batches = current.get('batches', []); new_batches = data['batches']
  # Match batches by id, not position: new imports are added at the front of the list.
  new_by_id = {b.get('id'): b for b in new_batches}
  old_ids = {b.get('id') for b in old_batches}
  if len(new_by_id) != len(new_batches): abort(400, description='Duplicate batch ids.')
  # HR may delete whole batches; any batch that remains must be unchanged apart from the allowed record fields.
  allowed = {'hrVerified', 'hrVerifiedAt', 'returnRequired', 'returnReason', 'returnFlaggedAt', 'endDate', 'previousEndDate', 'exitDate', 'exitPurpose', 'exitCategory'}
  for old_batch in old_batches:
   new_batch = new_by_id.get(old_batch.get('id'))
   if new_batch is None: continue  # batch deleted by HR
   if any(old_batch.get(k) != new_batch.get(k) for k in set(old_batch) | set(new_batch) if k != 'records'): abort(403, description='HR cannot edit existing import batch details.')
   old_records = {x.get('id'): x for x in old_batch.get('records', [])}
   new_records = {x.get('id'): x for x in new_batch.get('records', [])}
   if set(old_records) != set(new_records): abort(403, description='HR cannot add or delete records inside an existing batch.')
   for rid, old in old_records.items():
    new = new_records[rid]
    if any(old.get(k) != new.get(k) for k in set(old) | set(new) if k not in allowed): abort(403, description='HR can only verify submitted IDs or flag cards for return.')
    if new.get('endDate') != old.get('endDate') and not (new.get('returnRequired') and new.get('exitDate') == new.get('endDate') and new.get('exitPurpose')): abort(403, description='HR can only change the end date through the exit form.')
    if new.get('hrVerified') and new.get('status') != 'Submitted': abort(403, description='Only submitted ID cards can be confirmed by HR.')
    if new.get('returnRequired') and not re.search(r'full.?time|permanent', str(new.get('holderStatus') or new.get('position') or ''), re.I): abort(403, description='Card return flags are limited to full-time or permanent staff.')
  for batch in (b for b in new_batches if b.get('id') not in old_ids):
   for record in batch.get('records', []):
    if record.get('status') not in (None, 'Awaiting Capture') or any(record.get(k) for k in ('hrVerified', 'returnRequired', 'returnStatus')): abort(403, description='New HR imports may only create personnel awaiting capture.')
  data = {'batches': new_batches, 'history': current.get('history', [])}
 else:
  # Only HR may upload (add) or delete HR personnel batches/records; everyone else is view-only for uploads.
  old_batches = current.get('batches', []); new_batches = data['batches']
  if [b.get('id') for b in old_batches] != [b.get('id') for b in new_batches]: abort(403, description='Only HR can upload or delete HR personnel files.')
  for ob, nb in zip(old_batches, new_batches):
   if {x.get('id') for x in ob.get('records', [])} != {x.get('id') for x in nb.get('records', [])}: abort(403, description='Only HR can add or delete personnel records.')
 saved = sb.table('icms').update({'data': json.dumps({'batches': data['batches'], 'history': data['history']}), 'version': version + 1}).eq('id', 1).eq('version', version).execute()
 if not saved.data: abort(409, description='Another user changed ID-card records. Reload before editing.')
 return jsonify(version=version + 1)


@app.get('/api/icms/transfer-config')
def transfer_config():
 require('Admin', 'Physical Security')
 return jsonify(recipients=transfer_recipients())


def transfer_recipients():
 recipients = [x.strip() for x in os.environ.get('TRANSFER_RECIPIENTS', '').split(',') if x.strip()]
 if any(not re.fullmatch(r'[^\s@,;]+@[^\s@,;]+\.[^\s@,;]+', x) for x in recipients): abort(503, description='Transfer recipient configuration is invalid.')
 return recipients


@app.post('/api/icms/records/<record_id>/transfer')
def transfer(record_id):
 from email.message import EmailMessage
 require('Admin', 'Physical Security')
 recipients = transfer_recipients()
 host = os.environ.get('SMTP_HOST'); sender = os.environ.get('SMTP_FROM')
 if not recipients or not host or not sender: abort(503, description='Configure designated email recipients and SMTP before transferring ID details.')
 state = json.loads(get_icms()['data'])
 record = next((r for b in state['batches'] for r in b.get('records', []) if r.get('id') == record_id), None)
 if record is None: abort(404)
 if record.get('status') != 'Submitted' or not record.get('submittedAt'): abort(409, description='Only submitted IDs with a submission date can be transferred.')
 message = EmailMessage(); message['From'] = sender; message['To'] = ', '.join(recipients); message['Subject'] = 'Submitted ID card holder details'
 fields = [('Name', record.get('name')), ('Holder status', record.get('holderStatus', record.get('position'))), ('Employee ID', record.get('employeeId')), ('Department', record.get('department')), ('Course of study', record.get('courseOfStudy')), ('End date', record.get('endDate')), ('Card status', record.get('status')), ('Date of submission', record.get('submittedAt')), ('Sent by', user()['email'])]
 message.set_content('Submitted ID card transfer\n\n' + '\n'.join(label + ': ' + str(value or '—') for label, value in fields))
 try:
  mode = os.environ.get('SMTP_SECURITY', 'starttls')
  if mode not in ('starttls', 'ssl'): abort(503, description='SMTP_SECURITY must be starttls or ssl.')
  port = int(os.environ.get('SMTP_PORT', '465' if mode == 'ssl' else '587'))
  connection = smtplib.SMTP_SSL(host, port, timeout=20, context=ssl.create_default_context()) if mode == 'ssl' else smtplib.SMTP(host, port, timeout=20)
  with connection as smtp:
   if mode == 'starttls': smtp.starttls(context=ssl.create_default_context())
   if os.environ.get('SMTP_USERNAME'): smtp.login(os.environ['SMTP_USERNAME'], os.environ.get('SMTP_PASSWORD', ''))
   refused = smtp.send_message(message)
 except (smtplib.SMTPException, OSError, ValueError):
  app.logger.exception('ID card transfer email failed')
  return jsonify(message='The mail server did not confirm delivery. Check server logs before retrying.'), 502
 sent = datetime.now().astimezone().isoformat()
 entry = {'id': secrets.token_hex(12), 'action': 'ID details emailed', 'details': str(record.get('name', '')) + '; submitted ' + str(record['submittedAt']) + '; recipients ' + ', '.join(x for x in recipients if x not in refused), 'timestamp': sent, 'date': sent, 'by': user()['email']}
 for _ in range(5):  # compare-and-swap on the version column, retry if someone else saved meanwhile
  row = get_icms(); latest = json.loads(row['data'])
  latest['history'].insert(0, entry); latest['history'] = latest['history'][:300]
  saved = sb.table('icms').update({'data': json.dumps(latest), 'version': row['version'] + 1}).eq('id', 1).eq('version', row['version']).execute()
  if saved.data: break
 else:
  app.logger.error('Could not record ID transfer in history after retries')
 if refused: return jsonify(message='Some recipients were refused by the mail server. Check server logs before retrying.'), 502
 return jsonify(message='Email accepted by the mail server.', recipients=recipients)


def migrate_sqlite(source_path):
 """Copy existing PSP records from a local SQLite file into Supabase (over HTTPS)."""
 if not os.path.isfile(source_path):
  raise FileNotFoundError(f"SQLite database not found: {source_path}")
 source = sqlite3.connect(source_path)
 source.row_factory = sqlite3.Row

 def upsert(name, items, conflict):
  for i in range(0, len(items), 200):
   sb.table(name).upsert(items[i:i + 200], on_conflict=conflict).execute()
 try:
  tables = {r[0] for r in source.execute("SELECT name FROM sqlite_master WHERE type='table'")}
  if 'users' in tables:
   upsert('users', [dict(email=r['email'], password=r['password'], group_name=r['group_name']) for r in source.execute("SELECT email,password,group_name FROM users")], 'email')
  if 'visitors' in tables:
   upsert('visitors', [dict(id=r['id'], owner=r['owner'], data=r['data']) for r in source.execute("SELECT id,owner,data FROM visitors")], 'id')
  if 'icms' in tables:
   row = source.execute("SELECT id,data,version FROM icms WHERE id=1").fetchone()
   if row: upsert('icms', [dict(id=row['id'], data=row['data'], version=row['version'])], 'id')
  if 'notification_preferences' in tables:
   upsert('notification_preferences', [dict(email=r['email'], every_action=r['every_action'], status_changes=r['status_changes']) for r in source.execute("SELECT email,every_action,status_changes FROM notification_preferences")], 'email')
  # Login-attempt history is intentionally not migrated; it is temporary security state.
 finally:
  source.close()
 print("SQLite migration completed. Existing users, visitor records, ICMS data and notification preferences were copied.")


if __name__ == '__main__':
 parser = argparse.ArgumentParser(); parser.add_argument('--add-user'); parser.add_argument('--group', choices=GROUPS); parser.add_argument('--migrate-sqlite', metavar='PATH'); args = parser.parse_args()
 if args.migrate_sqlite:
  migrate_sqlite(args.migrate_sqlite)
 elif args.add_user:
  import getpass
  if not args.group: parser.error('--group is required')
  pw = getpass.getpass('New password (12+ characters): ')
  if len(pw) < 12: raise SystemExit('Password must have at least 12 characters.')
  sb.table('users').upsert({'email': args.add_user.lower().strip(), 'password': generate_password_hash(pw), 'group_name': args.group}, on_conflict='email').execute()
  print('User saved.')
 else: app.run(host='127.0.0.1', port=5000)
