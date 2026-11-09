import os, json, sqlite3, secrets, argparse, smtplib, ssl, re, io
from urllib.parse import quote
import requests
from postgrest.exceptions import APIError
from supabase import create_client
from datetime import datetime, timedelta
from flask import Flask, request, session, jsonify, redirect, render_template, abort, g
from werkzeug.security import generate_password_hash, check_password_hash

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


def client_ip():
 # Behind Vercel, remote_addr is the proxy. Set TRUST_PROXY=1 to use the forwarded client IP.
 if os.environ.get('TRUST_PROXY') == '1':
  fwd = request.headers.get('X-Forwarded-For', '')
  if fwd: return fwd.split(',')[0].strip()
 return request.remote_addr or 'unknown'


def send_mail(to, subject, body):
 host = os.environ.get('SMTP_HOST'); sender = os.environ.get('SMTP_FROM')
 if not to or not host or not sender: return False
 from email.message import EmailMessage
 msg = EmailMessage(); msg['From'] = sender; msg['To'] = to; msg['Subject'] = subject; msg.set_content(body)
 try:
  mode = os.environ.get('SMTP_SECURITY', 'starttls')
  if mode not in ('starttls', 'ssl'): return False
  port = int(os.environ.get('SMTP_PORT', '465' if mode == 'ssl' else '587'))
  conn = smtplib.SMTP_SSL(host, port, timeout=15, context=ssl.create_default_context()) if mode == 'ssl' else smtplib.SMTP(host, port, timeout=15)
  with conn as smtp:
   if mode == 'starttls': smtp.starttls(context=ssl.create_default_context())
   if os.environ.get('SMTP_USERNAME'): smtp.login(os.environ['SMTP_USERNAME'], os.environ.get('SMTP_PASSWORD', ''))
   smtp.send_message(msg)
  return True
 except Exception:
  app.logger.exception('VMS notification email failed'); return False


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
 purpose = re.sub('[^A-Za-z]', '', str(v.get('purpose') or 'VI'))[:2].title().ljust(2, 'X')
 code = f"{purpose}-{now.strftime('%d%m%y')}-{start:04d}" + (f"-{end:04d}" if count > 1 else '')
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
 storage_path = f"{quote(bucket, safe='')}/{quote(name, safe='')}"
 headers = {'apikey': SUPABASE_KEY, 'Authorization': f'Bearer {SUPABASE_KEY}',
            'Content-Type': f.mimetype or 'application/octet-stream', 'x-upsert': 'false'}
 try:
  response = requests.post(f"{SUPABASE_URL}/storage/v1/object/{storage_path}",
                           headers=headers, data=f.read(), timeout=30)
  response.raise_for_status()
 except requests.RequestException:
  app.logger.exception('Supabase attachment upload failed')
  abort(502, description='The attachment could not be stored. Check Supabase Storage configuration.')
 return jsonify(filename=f.filename, stored=name), 201


@app.get('/api/visitors/attachment/<filename>')
def download_visitor_attachment(filename):
 from flask import send_file
 safe = os.path.basename(filename)
 found = [(x['owner'], x['item']) for x in all_visitors() if x['item'].get('guestAttachment', {}).get('stored') == safe]
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
 download_name = found[0][1].get('guestAttachment', {}).get('filename', safe)
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
  for k in ('tagNo', 'laptop', 'laptopQuantity', 'laptopModel', 'laptopDetails', 'otherDevice', 'otherDeviceDetails', 'remarks'):
   if k in data: v[k] = data[k]
  v['timeIn'] = now
 if target == 'checked_out':
  v['timeOut'] = now
  for k in ('signature', 'signOutRemarks', 'signOutComment'):
   if k in data: v[k] = data[k]
 v['status'] = target
 saved = sb.table('visitors').update({'data': json.dumps(v), 'rev': rev + 1}).eq('id', id).eq('rev', rev).execute()
 if not saved.data: abort(409, description='This visitor was changed by someone else. Reload and try again.')
 for oid, item in others:
  sb.table('visitors').update({'data': json.dumps(item)}).eq('id', oid).execute()
 if target == 'approved':
  email_sent = send_mail(v.get('requestEmail'), 'Visitor request approved', f"Your visitor request has been approved.\nApproval code: {v.get('approvalCode')}\nPurpose: {v.get('purpose', '')}\nDate: {now}")
 if target in ('checked_in', 'checked_out', 'rejected'):
  notify_requester(v, 'Visitor request status updated', f"Visitor: {v.get('fullName', '')}\nStatus: {target.replace('_', ' ').title()}\nCode: {v.get('approvalCode') or 'Pending'}\nComment: {v.get('signOutComment') or v.get('rejectionReason') or ''}\nTime: {now}")
 return jsonify(visitor=v, emailSent=email_sent)


@app.route('/api/icms', methods=['PUT'])
def save_icms():
 require('Admin', 'Physical Security', 'HR'); data = request.get_json(silent=True)
 if not isinstance(data, dict) or not isinstance(data.get('batches'), list) or not isinstance(data.get('history'), list): abort(400)
 version = data.get('version')
 if not isinstance(version, int) or isinstance(version, bool): abort(409, description='Another user changed ID-card records. Reload before editing.')
 current = json.loads(get_icms()['data'])
 if user()['group'] == 'HR':
  old_batches = current.get('batches', []); new_batches = data['batches']
  if len(new_batches) < len(old_batches): abort(403, description='HR cannot remove existing personnel batches.')
  allowed = {'hrVerified', 'hrVerifiedAt', 'returnRequired', 'returnReason', 'returnFlaggedAt'}
  for index, old_batch in enumerate(old_batches):
   new_batch = new_batches[index]
   if any(old_batch.get(k) != new_batch.get(k) for k in set(old_batch) | set(new_batch) if k != 'records'): abort(403, description='HR cannot edit existing import batch details.')
   old_records = {x.get('id'): x for x in old_batch.get('records', [])}
   new_records = {x.get('id'): x for x in new_batch.get('records', [])}
   if set(old_records) != set(new_records): abort(403, description='HR cannot add or delete records inside an existing batch.')
   for rid, old in old_records.items():
    new = new_records[rid]
    if any(old.get(k) != new.get(k) for k in set(old) | set(new) if k not in allowed): abort(403, description='HR can only verify submitted IDs or flag cards for return.')
    if new.get('hrVerified') and new.get('status') != 'Submitted': abort(403, description='Only submitted ID cards can be confirmed by HR.')
    if new.get('returnRequired') and not re.search(r'full.?time|permanent', str(new.get('holderStatus') or new.get('position') or ''), re.I): abort(403, description='Card return flags are limited to full-time or permanent staff.')
  for batch in new_batches[len(old_batches):]:
   for record in batch.get('records', []):
    if record.get('status') not in (None, 'Awaiting Capture') or any(record.get(k) for k in ('hrVerified', 'returnRequired', 'returnStatus')): abort(403, description='New HR imports may only create personnel awaiting capture.')
  data = {'batches': new_batches, 'history': current.get('history', [])}
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
