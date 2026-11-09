import os, json, sqlite3, secrets, argparse, smtplib, ssl, re
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, session, jsonify, redirect, render_template, abort
from werkzeug.security import generate_password_hash, check_password_hash
app=Flask(__name__)
key=os.environ.get('SECRET_KEY')
if not key: raise RuntimeError('Set SECRET_KEY to a long random value before starting.')
app.config.update(SECRET_KEY=key, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.environ.get('HTTPS')=='1', PERMANENT_SESSION_LIFETIME=timedelta(hours=8), MAX_CONTENT_LENGTH=10*1024*1024)
DB=os.path.join(os.path.dirname(__file__),'psp.sqlite3')
GROUPS=['Admin','Physical Security','Reception','Staff','HR']
def db():
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c
def init():
 with db() as c:
  c.executescript('CREATE TABLE IF NOT EXISTS users(email TEXT PRIMARY KEY,password TEXT,group_name TEXT); CREATE TABLE IF NOT EXISTS visitors(id TEXT PRIMARY KEY,owner TEXT,data TEXT); CREATE TABLE IF NOT EXISTS icms(id INTEGER PRIMARY KEY,data TEXT,version INTEGER); CREATE TABLE IF NOT EXISTS attempts(ip TEXT,t REAL); CREATE TABLE IF NOT EXISTS notification_preferences(email TEXT PRIMARY KEY, every_action INTEGER NOT NULL DEFAULT 0, status_changes INTEGER NOT NULL DEFAULT 1);')
  c.execute('INSERT OR IGNORE INTO icms VALUES(1,?,0)',(json.dumps({'batches':[],'history':[]}),))
init()
def send_mail(to, subject, body):
 host=os.environ.get('SMTP_HOST'); sender=os.environ.get('SMTP_FROM')
 if not to or not host or not sender: return False
 from email.message import EmailMessage
 msg=EmailMessage(); msg['From']=sender; msg['To']=to; msg['Subject']=subject; msg.set_content(body)
 try:
  mode=os.environ.get('SMTP_SECURITY','starttls')
  if mode not in ('starttls','ssl'): return False
  port=int(os.environ.get('SMTP_PORT','465' if mode=='ssl' else '587'))
  conn=smtplib.SMTP_SSL(host,port,timeout=15,context=ssl.create_default_context()) if mode=='ssl' else smtplib.SMTP(host,port,timeout=15)
  with conn as smtp:
   if mode=='starttls': smtp.starttls(context=ssl.create_default_context())
   if os.environ.get('SMTP_USERNAME'): smtp.login(os.environ['SMTP_USERNAME'],os.environ.get('SMTP_PASSWORD',''))
   smtp.send_message(msg)
  return True
 except Exception:
  app.logger.exception('VMS notification email failed'); return False

def group_code(c, v, now):
 group=v.get('groupId') or v['id']
 existing=c.execute('SELECT data FROM visitors WHERE json_extract(data, "$.groupId")=? AND json_extract(data, "$.approvalCode") IS NOT NULL LIMIT 1',(group,)).fetchone()
 if existing: return json.loads(existing[0]).get('approvalCode')
 month=now.strftime('%m%y')
 # The sequence is the visitor's position in the monthly approved register.
 start=c.execute("SELECT COUNT(*) FROM visitors WHERE json_extract(data,'$.approvalMonth')=? AND json_extract(data,'$.status') IN ('approved','checked_in','checked_out') AND json_extract(data,'$.approvalSequence') IS NOT NULL",(month,)).fetchone()[0]+1
 members=c.execute('SELECT id,data FROM visitors WHERE json_extract(data, "$.groupId")=?',(group,)).fetchall()
 count=max(1,len(members)); end=start+count-1
 purpose=re.sub('[^A-Za-z]','',str(v.get('purpose') or 'VI'))[:2].title().ljust(2,'X')
 code=f"{purpose}-{now.strftime('%d%m%y')}-{start:04d}"+(f"-{end:04d}" if count>1 else '')
 for row in members:
  item=json.loads(row['data']); item.update(approvalCode=code,approvalMonth=month,approvalSequence=start,approvedGroupCount=count)
  c.execute('UPDATE visitors SET data=? WHERE id=?',(json.dumps(item),row['id']))
 return code

def notify_requester(v, subject, body, status_change=True):
 email=v.get('requestEmail')
 if not email: return
 with db() as c: pref=c.execute('SELECT * FROM notification_preferences WHERE email=?',(email,)).fetchone()
 every=v.get('notifyEveryAction') if 'notifyEveryAction' in v else (bool(pref['every_action']) if pref else False)
 status=v.get('notifyStatusChange') if 'notifyStatusChange' in v else (bool(pref['status_changes']) if pref else True)
 if every or (status_change and status): send_mail(email,subject,body)

def user():
 with db() as c: r=c.execute('SELECT email,group_name FROM users WHERE email=?',(session.get('email'),)).fetchone()
 return dict(email=r['email'],group=r['group_name']) if r else None
@app.before_request
def protect():
 if 'csrf' not in session: session['csrf']=secrets.token_hex(32)
 if request.method not in ('GET','HEAD','OPTIONS') and not secrets.compare_digest(request.headers.get('X-CSRF-Token',request.form.get('csrf','')),session['csrf']): abort(403)
 if request.path not in ('/','/login') and not request.path.startswith('/static/') and not user():
  if request.path.startswith('/api/'): abort(401)
  return redirect('/login')
@app.errorhandler(403)
@app.errorhandler(401)
@app.errorhandler(409)
@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(503)
def error(e): return jsonify(message=e.description),e.code
@app.context_processor
def context(): return {'user':user(),'csrf':session['csrf']}
def require(*groups):
 if not user() or user()['group'] not in groups: abort(403)
def rows():
 with db() as c:
  query='SELECT data FROM visitors'; args=()
  if user()['group'] in ('Staff','HR'): query+=' WHERE owner=?'; args=(user()['email'],)
  return [json.loads(r[0]) for r in c.execute(query,args)]
@app.route('/')
def home(): return redirect('/dashboard' if user() else '/login')
@app.route('/login',methods=['GET','POST'])
def login():
 if request.method=='GET': return render_template('login.html',error=None)
 email=request.form.get('email','').strip().lower(); password=request.form.get('password',''); now=datetime.now().timestamp()
 with db() as c:
  c.execute('DELETE FROM attempts WHERE t<?',(now-900,))
  if c.execute('SELECT count(*) FROM attempts WHERE ip=?',(request.remote_addr,)).fetchone()[0]>=10: return render_template('login.html',error='Too many attempts. Try again in 15 minutes.'),429
  r=c.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
  if not r or not check_password_hash(r['password'],password):
   c.execute('INSERT INTO attempts VALUES(?,?)',(request.remote_addr,now)); return render_template('login.html',error='Invalid email or password.'),401
 session.clear(); session['email']=email; session['csrf']=secrets.token_hex(32); session.permanent=True
 return redirect('/dashboard')
@app.post('/logout')
def logout(): session.clear(); return redirect('/login')
@app.get('/dashboard')
def dashboard():
 g=user()['group']; v=rows(); tiles=[]
 if g in ('Admin','Physical Security'): tiles.append(('Generate reports','VMS / ICMS','#report-chooser','Choose an application'))
 if g in ('Admin','Staff'): tiles.append(('My pending requests' if g=='Staff' else 'Pending requests','VMS','/vms?section='+('staff-log&status=pending' if g=='Staff' else 'approvals'),sum(x.get('status')=='pending' for x in v)))
 if g!='HR': tiles.append(('My visitors on site' if g=='Staff' else 'Visitors on site','VMS','/vms?section='+('staff-log&status=checked_in' if g=='Staff' else 'onsite'),sum(x.get('status')=='checked_in' for x in v)))
 if g in ('Admin','Physical Security','HR'):
  with db() as c: data=json.loads(c.execute('SELECT data FROM icms WHERE id=1').fetchone()[0])
  counts={'Awaiting Capture':0,'Pending':0,'Expired':0}
  for b in data['batches']:
   for r in b.get('records',[]):
    s=r.get('status','Awaiting Capture')
    try:
     if s!='Submitted' and datetime.fromisoformat(r.get('endDate','')[:10]).date()<datetime.now().date(): s='Expired'
    except (ValueError,TypeError): pass
    if s in counts: counts[s]+=1
  for title,status,section in [('ID cards to capture','Awaiting Capture','capture'),('ID cards ready for issuance','Pending','collection'),('Expired IDs','Expired','expired')]: tiles.append((title,'ICMS','/icms?section='+section,counts[status]))
  return_count=sum(1 for b in data['batches'] for r in b.get('records',[]) if r.get('returnRequired') and r.get('returnStatus')!='Returned')
  tiles.append(('ID cards pending return','ICMS','/icms?section=cardreturn',return_count))
 return render_template('dashboard.html',tiles=tiles)
@app.get('/vms')
def vms():
 require('Admin','Physical Security','Reception','Staff')
 return render_template('vms.html')
@app.route('/api/vms/notification-preferences',methods=['GET','PUT'])
def vms_notification_preferences():
 require('Admin','Physical Security','Staff')
 email=user()['email']
 if request.method=='GET':
  with db() as c: r=c.execute('SELECT * FROM notification_preferences WHERE email=?',(email,)).fetchone()
  return jsonify(every_action=bool(r['every_action']) if r else False,status_changes=bool(r['status_changes']) if r else True)
 data=request.get_json() or {}
 with db() as c: c.execute('INSERT INTO notification_preferences(email,every_action,status_changes) VALUES(?,?,?) ON CONFLICT(email) DO UPDATE SET every_action=excluded.every_action,status_changes=excluded.status_changes',(email,int(bool(data.get('every_action'))),int(bool(data.get('status_changes',True)))))
 return jsonify(saved=True)

@app.get('/icms')
def icms():
 require('Admin','Physical Security','HR')
 with db() as c: r=c.execute('SELECT * FROM icms WHERE id=1').fetchone()
 return render_template('ICMS.html',state=json.loads(r['data']),version=r['version'])
@app.route('/api/visitors',methods=['GET','POST'])
def visitors():
 if request.method=='GET':
  require('Admin','Physical Security','Reception','Staff')
  return jsonify(rows())
 require('Admin','Physical Security','Staff'); v=request.get_json();
 if not isinstance(v,dict) or not v.get('fullName'): abort(400,description='Visitor name is required.')
 v.update(id=secrets.token_hex(16),requestEmail=user()['email'],status='pending',timeIn=None,timeOut=None,approvedAt=None,approvedBy=None,tagNo='',approvalCode=None,createdAt=v.get('createdAt') or datetime.now().astimezone().isoformat())
 with db() as c: c.execute('INSERT INTO visitors VALUES(?,?,?)',(v['id'],user()['email'],json.dumps(v)))
 return jsonify(visitor=v),201
@app.post('/api/visitors/attachment')
def visitor_attachment():
 require('Admin','Physical Security','Staff')
 from werkzeug.utils import secure_filename
 f=request.files.get('file')
 if not f: abort(400,description='Choose a document to upload.')
 ext=os.path.splitext(secure_filename(f.filename))[1].lower()
 if ext not in ('.pdf','.doc','.docx','.xls','.xlsx','.csv','.txt'): abort(400,description='Unsupported attachment type.')
 folder=os.path.join(os.path.dirname(__file__),'private_uploads'); os.makedirs(folder,exist_ok=True)
 name=secrets.token_hex(16)+ext; f.save(os.path.join(folder,name))
 return jsonify(filename=f.filename,stored=name),201

@app.get('/api/visitors/attachment/<filename>')
def download_visitor_attachment(filename):
 from flask import send_from_directory
 safe=os.path.basename(filename)
 with db() as c:
  found=[]
  for row in c.execute('SELECT owner,data FROM visitors'):
   item=json.loads(row['data'])
   if item.get('guestAttachment',{}).get('stored')==safe: found.append((row['owner'],item))
 if not found: abort(404)
 if user()['group'] not in ('Admin','Physical Security') and not any(owner==user()['email'] for owner,item in found): abort(403)
 return send_from_directory(os.path.join(os.path.dirname(__file__),'private_uploads'),safe,as_attachment=True,download_name=found[0][1].get('guestAttachment',{}).get('filename',safe))

@app.route('/api/visitors/<id>',methods=['PATCH'])
@app.route('/api/visitors/<id>/<action>',methods=['PATCH'])
def change(id,action=None):
 g=user()['group']; data=request.get_json() or {}
 if action in ('check-in','check-out'): require('Admin','Physical Security')
 else: require('Admin')
 with db() as c:
  c.execute('BEGIN IMMEDIATE'); r=c.execute('SELECT data FROM visitors WHERE id=?',(id,)).fetchone()
  if not r: abort(404)
  v=json.loads(r[0]); old=v['status']; now=datetime.now().astimezone().isoformat()
  target={'reject':'rejected','check-in':'checked_in','check-out':'checked_out'}.get(action,data.get('status'))
  if (old,target) not in [('pending','approved'),('pending','rejected'),('approved','checked_in'),('checked_in','checked_out')]: abort(409,description='Invalid visitor status transition.')
  if target=='approved':
   v.update(approvedAt=now,approvedBy=user()['email'])
   code=group_code(c,v,datetime.now().astimezone())
   group=v.get('groupId') or v['id']
   group_rows=c.execute("SELECT id,data FROM visitors WHERE json_extract(data, '$.groupId')=? OR id=?",(group,group)).fetchall()
   for gr in group_rows:
    item=json.loads(gr['data']); item.update(status='approved',approvedAt=now,approvedBy=user()['email'],approvalCode=code)
    c.execute('UPDATE visitors SET data=? WHERE id=?',(json.dumps(item),gr['id']))
   v=json.loads(c.execute('SELECT data FROM visitors WHERE id=?',(id,)).fetchone()[0])
   email_sent=send_mail(v.get('requestEmail'),'Visitor request approved',f"Your visitor request has been approved.\nApproval code: {code}\nPurpose: {v.get('purpose','')}\nDate: {now}")
  if target=='rejected': v.update(rejectedAt=now,rejectedBy=user()['email'],rejectionReason=data.get('reason',''))
  if target=='checked_in':
   tag=str(data.get('tagNo',''))
   if not tag.isdigit() or not 0<=int(tag)<=100: abort(400,description='Choose a valid tag.')
   if any(json.loads(x[0]).get('status')=='checked_in' and str(json.loads(x[0]).get('tagNo'))==tag and (json.loads(x[0]).get('groupId') or json.loads(x[0]).get('id'))!=(v.get('groupId') or v.get('id')) for x in c.execute('SELECT data FROM visitors')): abort(409,description='Tag is already in use.')
   for k in ('tagNo','laptop','laptopQuantity','laptopModel','laptopDetails','otherDevice','otherDeviceDetails','remarks'): 
    if k in data: v[k]=data[k]
   v['timeIn']=now
  if target=='checked_out':
   v['timeOut']=now
   for k in ('signature','signOutRemarks','signOutComment'): 
    if k in data: v[k]=data[k]
  v['status']=target; c.execute('UPDATE visitors SET data=? WHERE id=?',(json.dumps(v),id))
  if target in ('checked_in','checked_out','rejected'):
   notify_requester(v,'Visitor request status updated',f"Visitor: {v.get('fullName','')}\nStatus: {target.replace('_',' ').title()}\nCode: {v.get('approvalCode') or 'Pending'}\nComment: {v.get('signOutComment') or v.get('rejectionReason') or ''}\nTime: {now}")
 return jsonify(visitor=v,emailSent=locals().get('email_sent',None))
@app.route('/api/icms',methods=['PUT'])
def save_icms():
 require('Admin','Physical Security','HR'); data=request.get_json()
 if not isinstance(data,dict) or not isinstance(data.get('batches'),list) or not isinstance(data.get('history'),list): abort(400)
 with db() as c:
  current=json.loads(c.execute('SELECT data FROM icms WHERE id=1').fetchone()[0])
  if user()['group']=='HR':
   old_batches=current.get('batches',[]); new_batches=data['batches']
   if len(new_batches)<len(old_batches): abort(403,description='HR cannot remove existing personnel batches.')
   allowed={'hrVerified','hrVerifiedAt','returnRequired','returnReason','returnFlaggedAt'}
   for index,old_batch in enumerate(old_batches):
    new_batch=new_batches[index]
    if any(old_batch.get(k)!=new_batch.get(k) for k in set(old_batch)|set(new_batch) if k!='records'): abort(403,description='HR cannot edit existing import batch details.')
    old_records={r.get('id'):r for r in old_batch.get('records',[])}
    new_records={r.get('id'):r for r in new_batch.get('records',[])}
    if set(old_records)!=set(new_records): abort(403,description='HR cannot add or delete records inside an existing batch.')
    for rid,old in old_records.items():
     new=new_records[rid]
     if any(old.get(k)!=new.get(k) for k in set(old)|set(new) if k not in allowed): abort(403,description='HR can only verify submitted IDs or flag cards for return.')
     if new.get('hrVerified') and new.get('status')!='Submitted': abort(403,description='Only submitted ID cards can be confirmed by HR.')
     if new.get('returnRequired') and not re.search(r'full.?time|permanent',str(new.get('holderStatus') or new.get('position') or ''),re.I): abort(403,description='Card return flags are limited to full-time or permanent staff.')
   for batch in new_batches[len(old_batches):]:
    for record in batch.get('records',[]):
     if record.get('status') not in (None,'Awaiting Capture') or any(record.get(k) for k in ('hrVerified','returnRequired','returnStatus')): abort(403,description='New HR imports may only create personnel awaiting capture.')
   data={'batches':new_batches,'history':current.get('history',[])}
  cur=c.execute('UPDATE icms SET data=?,version=version+1 WHERE id=1 AND version=?',(json.dumps({'batches':data['batches'],'history':data['history']}),data.get('version')))
  if not cur.rowcount: abort(409,description='Another user changed ID-card records. Reload before editing.')
 return jsonify(version=data['version']+1)
@app.get('/api/icms/transfer-config')
def transfer_config():
 require('Admin','Physical Security')
 return jsonify(recipients=transfer_recipients())
def transfer_recipients():
 import re
 recipients=[x.strip() for x in os.environ.get('TRANSFER_RECIPIENTS','').split(',') if x.strip()]
 if any(not re.fullmatch(r'[^\s@,;]+@[^\s@,;]+\.[^\s@,;]+',x) for x in recipients): abort(503,description='Transfer recipient configuration is invalid.')
 return recipients
@app.post('/api/icms/records/<record_id>/transfer')
def transfer(record_id):
 import smtplib, ssl
 from email.message import EmailMessage
 require('Admin','Physical Security')
 recipients=transfer_recipients()
 host=os.environ.get('SMTP_HOST'); sender=os.environ.get('SMTP_FROM')
 if not recipients or not host or not sender: abort(503,description='Configure designated email recipients and SMTP before transferring ID details.')
 with db() as c: state=json.loads(c.execute('SELECT data FROM icms WHERE id=1').fetchone()[0])
 record=next((r for b in state['batches'] for r in b.get('records',[]) if r.get('id')==record_id),None)
 if record is None: abort(404)
 if record.get('status')!='Submitted' or not record.get('submittedAt'): abort(409,description='Only submitted IDs with a submission date can be transferred.')
 message=EmailMessage(); message['From']=sender; message['To']=', '.join(recipients); message['Subject']='Submitted ID card holder details'
 fields=[('Name',record.get('name')),('Holder status',record.get('holderStatus',record.get('position'))),('Employee ID',record.get('employeeId')),('Department',record.get('department')),('Course of study',record.get('courseOfStudy')),('End date',record.get('endDate')),('Card status',record.get('status')),('Date of submission',record.get('submittedAt')),('Sent by',user()['email'])]
 message.set_content('Submitted ID card transfer\n\n'+'\n'.join(label+': '+str(value or '—') for label,value in fields))
 try:
  mode=os.environ.get('SMTP_SECURITY','starttls')
  if mode not in ('starttls','ssl'): abort(503,description='SMTP_SECURITY must be starttls or ssl.')
  port=int(os.environ.get('SMTP_PORT','465' if mode=='ssl' else '587'))
  connection=smtplib.SMTP_SSL(host,port,timeout=20,context=ssl.create_default_context()) if mode=='ssl' else smtplib.SMTP(host,port,timeout=20)
  with connection as smtp:
   if mode=='starttls': smtp.starttls(context=ssl.create_default_context())
   if os.environ.get('SMTP_USERNAME'): smtp.login(os.environ['SMTP_USERNAME'],os.environ.get('SMTP_PASSWORD',''))
   refused=smtp.send_message(message)
 except (smtplib.SMTPException,OSError,ValueError):
  app.logger.exception('ID card transfer email failed')
  return jsonify(message='The mail server did not confirm delivery. Check server logs before retrying.'),502
 with db() as c:
  c.execute('BEGIN IMMEDIATE')
  row=c.execute('SELECT data FROM icms WHERE id=1').fetchone(); latest=json.loads(row[0]); sent=datetime.now().astimezone().isoformat()
  latest['history'].insert(0,{'id':secrets.token_hex(12),'action':'ID details emailed','details':str(record.get('name',''))+'; submitted '+str(record['submittedAt'])+'; recipients '+', '.join(x for x in recipients if x not in refused),'timestamp':sent,'date':sent,'by':user()['email']})
  latest['history']=latest['history'][:300]
  c.execute('UPDATE icms SET data=?,version=version+1 WHERE id=1',(json.dumps(latest),))
 if refused: return jsonify(message='Some recipients were refused by the mail server. Check server logs before retrying.'),502
 return jsonify(message='Email accepted by the mail server.',recipients=recipients)

if __name__=='__main__':
 parser=argparse.ArgumentParser(); parser.add_argument('--add-user'); parser.add_argument('--group',choices=GROUPS); args=parser.parse_args()
 if args.add_user:
  import getpass
  if not args.group: parser.error('--group is required')
  pw=getpass.getpass('New password (12+ characters): ')
  if len(pw)<12: raise SystemExit('Password must have at least 12 characters.')
  with db() as c: c.execute('INSERT OR REPLACE INTO users VALUES(?,?,?)',(args.add_user.lower().strip(),generate_password_hash(pw),args.group))
  print('User saved.')
 else: app.run(host='127.0.0.1',port=5000)
