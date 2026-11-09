import json,os,sys,tempfile,unittest,re,subprocess
from unittest.mock import patch,MagicMock
from pathlib import Path
os.environ.setdefault('SECRET_KEY','test-key-only')
sys.path.insert(0,os.path.dirname(os.path.dirname(__file__)))
import app
class PortalTests(unittest.TestCase):
 def setUp(self):
  self.old=app.DB;self.tmp=tempfile.TemporaryDirectory();app.DB=os.path.join(self.tmp.name,'test.sqlite');app.init()
  with app.db() as c:
   for email,group in [('admin@example.com','Admin'),('security@example.com','Physical Security'),('staff@example.com','Staff')]: c.execute('INSERT INTO users VALUES(?,?,?)',(email,app.generate_password_hash('a-long-test-password'),group))
  self.admin,self.headers=self.login('admin@example.com');self.staff,self.staffheaders=self.login('staff@example.com')
 def tearDown(self): app.DB=self.old;self.tmp.cleanup()
 def login(self,email):
  c=app.app.test_client();c.get('/login')
  with c.session_transaction() as session: token=session['csrf']
  self.assertEqual(c.post('/login',data={'email':email,'password':'a-long-test-password','csrf':token}).status_code,302)
  with c.session_transaction() as session: token=session['csrf']
  return c,{'X-CSRF-Token':token}
 def seed(self,status='Submitted'):
  record={'id':'R1','name':'Example Holder','holderStatus':'Contract staff','employeeId':'E01','department':'IT','endDate':'2027-01-10','status':status,'submittedAt':'2026-10-12T11:00:00+01:00'}
  with app.db() as c: c.execute('UPDATE icms SET data=?',(json.dumps({'batches':[{'records':[record]}],'history':[]}),))
 def test_chooser_and_permissions(self):
  html=self.admin.get('/dashboard').text
  self.assertIn('Generate reports',html);self.assertIn('reportChooser',html);self.assertIn('/icms?section=reports',html)
  self.assertNotIn('reportChooser',self.staff.get('/dashboard').text)
  self.assertEqual(self.staff.get('/icms?section=reports').status_code,403)
  self.assertEqual(self.staff.post('/api/icms/records/R1/transfer',headers=self.staffheaders).status_code,403)
 def test_transfer_details_and_date(self):
  self.seed();smtp=MagicMock();smtp.__enter__.return_value=smtp;smtp.send_message.return_value={}
  with patch.dict(os.environ,{'TRANSFER_RECIPIENTS':'hr@example.com,security@example.com','SMTP_HOST':'mail.example.com','SMTP_FROM':'portal@example.com'}),patch('smtplib.SMTP',return_value=smtp):
   response=self.admin.post('/api/icms/records/R1/transfer',headers=self.headers)
  self.assertEqual(response.status_code,200)
  message=smtp.send_message.call_args[0][0];body=message.get_content()
  self.assertIn('Example Holder',body);self.assertIn('2026-10-12T11:00:00+01:00',body);self.assertIn('Contract staff',body)
  self.assertIn('hr@example.com',message['To']);smtp.starttls.assert_called_once()
  with app.db() as c: state=json.loads(c.execute('SELECT data FROM icms').fetchone()[0]);self.assertEqual(len(state['history']),1)
 def test_missing_config_and_csrf(self):
  self.seed()
  with patch.dict(os.environ,{'TRANSFER_RECIPIENTS':'','SMTP_HOST':''}): self.assertEqual(self.admin.post('/api/icms/records/R1/transfer',headers=self.headers).status_code,503)
  self.assertEqual(self.admin.post('/api/icms/records/R1/transfer').status_code,403)
 def test_only_submitted_cards(self):
  self.seed('Collected')
  with patch.dict(os.environ,{'TRANSFER_RECIPIENTS':'hr@example.com','SMTP_HOST':'mail.example.com','SMTP_FROM':'portal@example.com'}),patch('smtplib.SMTP') as smtp:
   self.assertEqual(self.admin.post('/api/icms/records/R1/transfer',headers=self.headers).status_code,409);smtp.assert_not_called()
 def test_report_markup_and_javascript(self):
  for route in ['/dashboard','/icms?section=reports','/vms?section=reports']:
   html=self.admin.get(route).text
   for n,script in enumerate(re.findall(r'<script(?:\s[^>]*)?>(.*?)</script>',html,re.S)):
    path=os.path.join(self.tmp.name,f'script{n}.js');Path(path).write_text(script)
    subprocess.run(['node','--check',path],check=True,capture_output=True)
   if '/icms' in route:
    self.assertLess(html.index('id="icmsReportCharts"'),html.index('id="icmsReportTable"'))
    self.assertIn('mapped.status',html);self.assertNotIn('mapped.position',html)
   if '/vms' in route: self.assertLess(html.index('id="vmsReportCharts"'),html.index('id="reportTbody"'))
if __name__=='__main__': unittest.main()
