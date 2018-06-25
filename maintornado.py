import datetime
import time
import tornado.escape
import tornado.ioloop
import tornado.web
import os
import io
import string
import random
import requests
import MySQLdb
import hashlib
import base64
import hmac
import uuid
import boto
from dateutil import parser
import threading

root = os.path.dirname(__file__)

awsid = os.environ['AWSID']
key = os.environ['AWSKEY']
dbhost = os.environ['DBHOST']
dbuser = os.environ['DBUSER']
dbpasswd = os.environ['DBPASSWD']
dbname = os.environ['DBNAME']
bucketname = os.environ['BUCKET']
expiration = int(os.environ['EXPIRATION_TIME'])
maxsize = int(os.environ['MAXSIZE'])
fileage = int(os.environ['FILEAGE'])



def s3thread(akey, skey, fileage, bucketname):
    while True:
        conn = boto.connect_s3(akey, skey)
        bucket = conn.get_bucket(bucketname)
        for file in bucket.list():
            if file.key.endswith("fastq.gz") or file.key.endswith("fq.gz"):
                age = datetime.datetime.now() - parser.parse(file.last_modified).replace(tzinfo=None)
                if age.days > fileage:
                    bucket.delete_key(file)
        
        time.sleep(3000)

def getConnection():
    db = MySQLdb.connect(host=dbhost,    # your host, usually localhost
                     user=dbuser,         # your username
                     passwd=dbpasswd,  # your password
                     db=dbname)        # name of the data base
    return(db)

def getPolicy(username, password, self):
    self.set_header("Access-Control-Allow-Origin", "*")
    db = getConnection()
    cur = db.cursor()
    query = "SELECT * FROM userinfo WHERE username='%s'" % (username);
    cur.execute(query)
    
    for res in cur:
        saltpass = res[4]
        salt = res[5]
        fname = res[3]
        lname = res[4]
        uid = res[9]
        h = hashlib.md5()
        h.update((password+salt).encode('utf-8'))
        sp = h.hexdigest()
    
    cur.close()
    db.close()
    
    if(saltpass == sp):
        t = datetime.datetime.utcnow() + datetime.timedelta(minutes = expiration)
        amzdate = t.strftime('%Y-%m-%dT%H:%M:%SZ')
        
        policy_document = {"expiration": amzdate,
          "conditions": [ 
            {"bucket": bucketname}, 
            ["starts-with", "$key", uid+"/"],
            {"acl": "private"},
            {"success_action_redirect": "success.html"},
            ["starts-with", "$Content-Type", ""],
            ["content-length-range", 0, maxsize]
          ]
        }
        
        policy = base64.b64encode(str(policy_document).encode('utf-8'))
        signature = base64.b64encode(hmac.new(key, policy, hashlib.sha1).digest())
        
        response = { 'action' : "generate policy",
                     'status' : "success",
                     'cid': awsid,
                     'username': username,
                     'bucket': bucketname,
                     'uid': uid,
                     'policy': policy.decode("utf-8") ,
                     'expiration' : amzdate,
                     'signature': signature.decode("utf-8") }
        self.write(response)
    else:
        response = { 'action': 'create policy',
             'task': username,
             'status': 'error',
             'message': 'user not validated'}
        self.write(response)

def createUser(username, password, firstname, lastname, email, self):
    self.set_header("Access-Control-Allow-Origin", "*")
    db = getConnection()
    cur = db.cursor()
    
    query = "SELECT * FROM userinfo WHERE username='%s'" % (username);
    cur.execute(query)
    
    if cur.rowcount > 0:
        response = { 'action': 'create user',
             'task': username,
             'status': 'error',
             'message': 'username already taken'}
        self.write(response)
    else:
        salt = uuid.uuid4().hex
        h = hashlib.md5()
        h.update((password+salt).encode('utf-8'))
        saltpass = h.hexdigest()
        
        h2 = hashlib.md5()
        h2.update((username+salt).encode('utf-8'))
        uid = h2.hexdigest()
        
        query = "INSERT INTO userinfo (username, firstname, lastname, password, salt, email, role, uuid) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')" % (username, firstname, lastname, saltpass, salt, email, "user", uid);
        cur.execute(query)
        db.commit()
        cur.close()
        db.close()
        
        response = { 'action': 'create user',
             'task': username,
             'status': 'success',
             'message': uid}
        self.write(response)

def listFiles(username, password, self):
    self.set_header("Access-Control-Allow-Origin", "*")
    db = getConnection()
    cur = db.cursor()
    query = "SELECT * FROM userinfo WHERE username='%s'" % (username);
    cur.execute(query)
    
    for res in cur:
        saltpass = res[4]
        salt = res[5]
        fname = res[3]
        lname = res[4]
        uid = res[9]
        h = hashlib.md5()
        h.update((password+salt).encode('utf-8'))
        sp = h.hexdigest()
    
    cur.close()
    db.close()
    
    if(saltpass == sp):
        filelist = []
        sizelist = []
        conn = boto.connect_s3(awsid, key)
        bucket = conn.get_bucket(bucketname)
        for file in bucket.list(uid+"/", "/"):
            sizelist.append(sizeof_fmt(file.size))
            filelist.append(file.key.replace(uid+"/", ""))
        
        response = { 'action': 'list files',
             'task': username,
             'status': 'success',
             'filenames': filelist,
             'filesize': sizelist}
        self.write(response)
    else:
        response = { 'action': 'list files',
             'task': username,
             'status': 'error',
             'message': 'credentials not matching'}
        self.write(response)

def deleteFile(username, password, finame, self):
    self.set_header("Access-Control-Allow-Origin", "*")
    db = getConnection()
    cur = db.cursor()
    query = "SELECT * FROM userinfo WHERE username='%s'" % (username);
    cur.execute(query)
    
    for res in cur:
        saltpass = res[4]
        salt = res[5]
        fname = res[3]
        lname = res[4]
        uid = res[9]
        h = hashlib.md5()
        h.update((password+salt).encode('utf-8'))
        sp = h.hexdigest()
    
    cur.close()
    db.close()
    
    if(saltpass == sp):
        filelist = []
        sizelist = []
        conn = boto.connect_s3(awsid, key)
        bucket = conn.get_bucket(bucketname)
        
        k = boto.s3.connection.Key(bucket)
        k.key = uid+"/"+finame
        bucket.delete_key(k)
        
        response = { 'action': 'list files',
             'task': username,
             'status': 'success',
             'filename': finame}
        self.write(response)
    else:
        response = { 'action': 'delete file',
             'task': username,
             'status': 'error',
             'message': 'credentials not matching'}
        self.write(response)

def sizeof_fmt(num, suffix='B'):
    for unit in ['','K','M','G','T','P','E','Z']:
        if abs(num) < 1024.0:
            return("%3.1f%s%s" % (num, unit, suffix))
        num /= 1024.0
    return("%.1f%s%s" % (num, 'Y', suffix))


class SignAuth(tornado.web.RequestHandler):
    def get(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        to_sign = str(self.get_argument('to_sign')).encode('utf-8')
        
        aws_secret = key
        date_stamp = datetime.datetime.strptime(self.get_argument('datetime'), '%Y%m%dT%H%M%SZ').strftime('%Y%m%d')
        region = 'us-east-1'
        service = 's3'
        
        # Key derivation functions. See:
        # http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
        
        def sign(key, msg):
            return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()
        
        def getSignatureKey(key, date_stamp, regionName, serviceName):
            kDate = sign(('AWS4' + key).encode('utf-8'), date_stamp)
            kRegion = sign(kDate, regionName)
            kService = sign(kRegion, serviceName)
            kSigning = sign(kService, 'aws4_request')
            return kSigning
        
        signing_key = getSignatureKey(aws_secret, date_stamp, region, service)
        
        # Sign to_sign using the signing_key
        signature = hmac.new(
            signing_key,
            to_sign,
            hashlib.sha256
        ).hexdigest()
        
        self.set_header('Content-Type', "text/plain")
        self.write(signature)

class CreateUserHandler(tornado.web.RequestHandler):
    def get(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        username = self.get_argument('username', True)
        password = self.get_argument('password', True)
        firstname = self.get_argument('firstname', True)
        lastname = self.get_argument('lastname', True)
        email = self.get_argument('email', True)
        invitationKey = self.get_argument('invitationKey', True)
        
        if invitationKey == 'charon2018':
            createUser(username, password, firstname, lastname, email, self)
        else:
            response = { 'action': 'create user',
                 'task': username,
                 'status': 'error',
                 'message': 'invitationKey needed'}
            self.write(response)

class ListHandler(tornado.web.RequestHandler):
    def get(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        username = self.get_argument('username', True)
        password = self.get_argument('password', True)
        listFiles(username, password, self)

class DeleteHandler(tornado.web.RequestHandler):
    def get(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        username = self.get_argument('username', True)
        password = self.get_argument('password', True)
        filename = self.get_argument('file', True)
        deleteFile(username, password, filename, self)

class LoginHandler(tornado.web.RequestHandler):
    def get(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        username = self.get_argument('username', True)
        password = self.get_argument('password', True)
        
        db = getConnection()
        cur = db.cursor()
        query = "SELECT * FROM userinfo WHERE username='%s'" % (username);
        
        cur.execute(query)
        
        if cur.rowcount > 0:
            for res in cur:
                saltpass = res[4]
                salt = res[5]
                fname = res[3]
                lname = res[4]
                uid = res[9]
                h = hashlib.md5()
                h.update((password+salt).encode('utf-8'))
                sp = h.hexdigest()
                
                if(saltpass == sp):
                    response = { 'action': 'login',
                       'task': username,
                       'status': 'success',
                       'message': uid}
                else:
                    response = { 'action': 'login',
                       'task': username,
                       'status': 'failed',
                       'message': 'login failed'}
        else:
            response = { 'action': 'login',
               'task': username,
               'status': 'failed',
               'message': 'login failed'}
               
        self.write(response)
        
        cur.close()
        db.close()

class AdminHandler(tornado.web.RequestHandler):
    def get(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        username = self.get_argument('username', True)
        password = self.get_argument('password', True)
        
        db = getConnection()
        cur = db.cursor()
        query = "SELECT * FROM userinfo WHERE username='%s'" % (username);
        cur.execute(query)
        
        for res in cur:
            saltpass = res[4]
            salt = res[5]
            fname = res[3]
            lname = res[4]
            role = res[8]
            uid = res[9]
            h = hashlib.md5()
            h.update((password+salt).encode('utf-8'))
            sp = h.hexdigest()
        
        cur.close()
        
        if(saltpass == sp and role == "admin"):
            query = "SELECT username, firstname, lastname, email, date, uuid FROM userinfo";
            cur = db.cursor()
            cur.execute(query)
            
            for res in cur:
                query = "SELECT username, firstname, lastname, email, date, uuid FROM jobqueue WHERE userid='%s'" % (res[6]);
                cur2 = db.cursor()
                cur2.execute(query)
                cur2.close()
        
        else:
            response = { 'action': 'login',
               'task': username,
               'status': 'failed',
               'message': 'login failed'}
        
        self.write(response)

class VersionHandler(tornado.web.RequestHandler):
    def get(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        response = { 'version': '1',
                     'last_build':  datetime.date.today().isoformat() }
        self.write(response)

class SignHandler(tornado.web.RequestHandler):
    def post(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        data = tornado.escape.json_decode(self.request.body)
        getPolicy(data["username"], data["password"], self)
    
    def get(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        username = self.get_argument('username', True)
        password = self.get_argument('password', True)
        getPolicy(username, password, self)

application = tornado.web.Application([
    (r"/charon/sign_auth", SignAuth),
    (r"/charon/version", VersionHandler),
    (r"/charon/admin", AdminHandler),
    (r"/charon/files", ListHandler),
    (r"/charon/delete", DeleteHandler),
    (r"/charon/createuser", CreateUserHandler),
    (r"/charon/signpolicy", SignHandler),
    (r"/charon/login", LoginHandler),
    (r"/charon/(.*)", tornado.web.StaticFileHandler, dict(path=root))
])

ec2t = threading.Thread(target=s3thread, args=(awsid, key, fileage, bucketname, ))
ec2t.start()

if __name__ == "__main__":
    application.listen(5000)
    tornado.ioloop.IOLoop.instance().start()
