import datetime
import hashlib
import hmac
import os
import base64
import threading
import time
import uuid
import tornado.escape
import tornado.ioloop
import tornado.web
import json
import pymysql
from pymysql import cursors
import boto3

#from dotenv import load_dotenv
#load_dotenv()

root = os.path.dirname(__file__)

awsid = os.environ['AWSID']
key = os.environ['AWSKEY']
dbhost = os.environ['DBHOST']
dbuser = os.environ['DBUSER']
dbpasswd = os.environ['DBPASSWD']
dbname = os.environ['DBNAME']
bucketname = os.environ['BUCKET']
base_url = os.environ['BASE_URL']
expiration = int(os.environ['EXPIRATION_TIME'])
maxsize = int(os.environ['MAXSIZE'])
fileage = int(os.environ['FILEAGE'])

def s3thread(akey, skey, fileage, bucketname):
    s3 = boto3.resource('s3', aws_access_key_id=akey, aws_secret_access_key=skey)
    bucket = s3.Bucket(bucketname)

    while True:
        for obj in bucket.objects.all():
            if obj.key.endswith("fastq.gz") or obj.key.endswith("fq.gz"):
                age = datetime.datetime.now() - obj.last_modified.replace(tzinfo=None)
                if age.days > fileage:
                    obj.delete()
        time.sleep(3000)

def getConnection():
    return pymysql.connect(host=dbhost,
                           user=dbuser,
                           password=dbpasswd,
                           db=dbname,
                           cursorclass=pymysql.cursors.DictCursor)

def getPolicy(username, password, handler):
    handler.set_header("Access-Control-Allow-Origin", "*")
    uid = None
    saltpass = None
    
    # Using a context manager for database connection
    with getConnection() as db:
        with db.cursor(cursors.DictCursor) as cur:
            # Use a parameterized query
            query = "SELECT uuid, password, salt FROM userinfo WHERE username = %s"
            cur.execute(query, (username,))
            res = cur.fetchone()  # Assuming 'username' is unique
            
            if res:
                saltpass = res['password']
                salt = res['salt']
                uid = res['uuid']
                # Using hashlib for hashing
                sp = hashlib.md5((password + salt).encode('utf-8')).hexdigest()
                
    # Proceed only if user is validated   
    if saltpass and saltpass == sp and uid:
        t = datetime.datetime.utcnow() + datetime.timedelta(minutes=expiration)
        amzdate = t.strftime('%Y-%m-%dT%H:%M:%SZ')
        
        policy_document = {
            "expiration": amzdate,
            "conditions": [
                {"bucket": bucketname},
                ["starts-with", "$key", uid + "/"],
                {"acl": "private"},
                {"success_action_redirect": "success.html"},
                ["starts-with", "$Content-Type", ""],
                ["content-length-range", 0, maxsize]
            ]
        }
        
        # Correct handling of bytes
        policy_encoded = base64.b64encode(json.dumps(policy_document).encode('utf-8')).decode('utf-8')
        signature = base64.b64encode(hmac.new(key.encode('utf-8'), policy_encoded.encode('utf-8'), hashlib.sha1).digest()).decode('utf-8')
        
        response = {
            'action': "generate policy",
            'status': "success",
            'cid': awsid,
            'username': username,
            'bucket': bucketname,
            'uid': uid,
            'policy': policy_encoded,
            'expiration': amzdate,
            'signature': signature
        }
        
    else:
        response = {
            'action': 'create policy',
            'task': username,
            'status': 'error',
            'message': 'user not validated'
        }
        
    handler.write(response)

def createUser(username, password, firstname, lastname, email, handler):
    handler.set_header("Access-Control-Allow-Origin", "*")
    db = getConnection()
    try:
        with db.cursor() as cur:
            # Use parameterized queries to avoid SQL injection risks.
            query = "SELECT * FROM userinfo WHERE username = %s"
            cur.execute(query, (username,))
            result = cur.fetchone()

            if result is not None:
                response = {'action': 'create user',
                            'task': username,
                            'status': 'error',
                            'message': 'username already taken'}
                handler.write(response)
            else:
                salt = uuid.uuid4().hex
                h = hashlib.md5()
                h.update((password + salt).encode('utf-8'))
                saltpass = h.hexdigest()

                h2 = hashlib.md5()
                h2.update((username + salt).encode('utf-8'))
                uid = h2.hexdigest()

                # Again, use parameterized queries to safely insert user data.
                insert_query = "INSERT INTO userinfo (username, firstname, lastname, password, salt, email, role, uuid) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
                cur.execute(insert_query, (username, firstname, lastname, saltpass, salt, email, "user", uid))
                db.commit()

                response = {'action': 'create user',
                            'task': username,
                            'status': 'success',
                            'message': uid}
                handler.write(response)
    finally:
        db.close()


def listFiles(username, password, prefix, handler):
    handler.set_header("Access-Control-Allow-Origin", "*")
    db = getConnection()
    try:
        with db.cursor() as cur:
            # Use parameterized queries to safeguard against SQL injection
            query = "SELECT * FROM userinfo WHERE username = %s"
            cur.execute(query, (username,))
            res = cur.fetchone()

            if res:
                saltpass, salt, uid = res['password'], res['salt'], res['uuid']
                h = hashlib.md5()
                h.update((password + salt).encode('utf-8'))
                sp = h.hexdigest()

                if saltpass == sp:
                    # Using boto3 to list objects in S3 bucket
                    s3_client = boto3.client('s3', aws_access_key_id=awsid, aws_secret_access_key=key)
                    #response = s3_client.list_objects_v2(Bucket=bucketname, Prefix=f"{uid}/")
                    filelist, sizelist = list_all_objects(s3_client, bucketname, uid, prefix)
                    
                    response = {'action': 'list files',
                                'task': username,
                                'status': 'success',
                                'filenames': filelist,
                                'filesize': sizelist}
                    handler.write(response)
                else:
                    error_response(handler, 'list file', 'credentials not matching')
            else:
                error_response(handler, 'list file', 'user not found')
    finally:
        db.close()

def list_all_objects(s3_client, bucketname, uid, prefix):
    filelist = []
    sizelist = []
    
    # Initialize the paginator
    paginator = s3_client.get_paginator('list_objects_v2')
    
    # Create a PageIterator from the Paginator
    page_iterator = paginator.paginate(Bucket=bucketname, Prefix=f"{uid}/{prefix}")
    
    # Iterate through each page (each page can contain up to 1000 items)
    for page in page_iterator:
        if 'Contents' in page:
            for obj in page['Contents']:
                file_size = sizeof_fmt(obj['Size'])  # Ensure sizeof_fmt is defined or replace with appropriate format
                file_name = obj['Key'].replace(f"{uid}/", "")
                filelist.append(file_name)
                sizelist.append(file_size)
    
    return filelist, sizelist

def deleteFile(username, password, finame, handler):
    handler.set_header("Access-Control-Allow-Origin", "*")
    db = getConnection()
    try:
        with db.cursor() as cur:
            query = "SELECT * FROM userinfo WHERE username = %s"
            cur.execute(query, (username,))
            res = cur.fetchone()

            if res:
                saltpass, salt, uid = res['password'], res['salt'], res['uuid']
                h = hashlib.md5()
                h.update((password + salt).encode('utf-8'))
                sp = h.hexdigest()

                if saltpass == sp:
                    # Initialize S3 resource
                    s3_resource = boto3.resource('s3', aws_access_key_id=awsid, aws_secret_access_key=key)
                    obj = s3_resource.Object(bucketname, f"{uid}/{finame}")
                    obj.delete()  # delete the file

                    response = {'action': 'delete file',
                                'task': username,
                                'status': 'success',
                                'filename': finame}
                    handler.write(response)
                else:
                    error_response(handler, 'delete', 'credentials not matching')
            else:
                error_response(handler, 'delete', 'user not found')
    finally:
        db.close()

def error_response(handler, action, message):
    """Utility function to send an error response"""
    handler.write({
        'action': action,
        'status': 'error',
        'message': message
    })

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
        prefix = self.get_argument('prefix', "")
        listFiles(username, password, prefix, self)

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
        
        try:
            with db.cursor() as cur:
                # Use a parameterized query to prevent SQL injection.
                query = "SELECT * FROM userinfo WHERE username = %s"
                cur.execute(query, (username,))
                res = cur.fetchone()  # Fetch the first row only.
                
                if res is not None:
                    # Store each field in its respective variable for better readability.
                    saltpass = res['password']  # Adjust the index as per your DB schema, using string keys for clearer code.
                    salt = res['salt']
                    uid = res['uuid']  # Assuming 'uuid' is the field name in your userinfo table.
                    
                    # Create a hash with the provided password and the salt from the DB.
                    h = hashlib.md5()
                    h.update((password + salt).encode('utf-8'))
                    sp = h.hexdigest()
                    
                    # Compare the hash of the provided password with the one stored in DB.
                    if saltpass == sp:
                        response = {
                            'action': 'login',
                            'task': username,
                            'status': 'success',
                            'message': uid
                        }
                    else:
                        response = {
                            'action': 'login',
                            'task': username,
                            'status': 'failed',
                            'message': 'login failed - incorrect password'
                        }
                else:
                    response = {
                        'action': 'login',
                        'task': username,
                        'status': 'failed',
                        'message': 'login failed - user not found'
                    }

                self.write(response)
                
        finally:
            db.close()

class AdminHandler(tornado.web.RequestHandler):
    def get(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        username = self.get_argument('username', True)
        password = self.get_argument('password', True)

        db = getConnection()
        try:
            with db.cursor() as cur:
                # Using parameterized queries to enhance security
                query = "SELECT * FROM userinfo WHERE username = %s"
                cur.execute(query, (username,))
                res = cur.fetchone()  # Fetching the single result

                if res:
                    saltpass, salt, role, uid = res['password'], res['salt'], res['role'], res['uuid']
                    # Hashing the password with salt for verification
                    h = hashlib.md5()
                    h.update((password + salt).encode('utf-8'))
                    sp = h.hexdigest()

                    if saltpass == sp and role == "admin":
                        users_info = self.fetch_users(db)
                        self.write({
                            'action': 'admin',
                            'status': 'success',
                            'users': users_info
                        })
                    else:
                        self.error_response('login failed or not authorized')
                else:
                    self.error_response('user not found')
        finally:
            db.close()

    def fetch_users(self, db):
        """Fetch users' information from database"""
        users_info = []
        with db.cursor() as cur:
            query = "SELECT username, firstname, lastname, email, date, uuid FROM userinfo"
            cur.execute(query)
            for res in cur.fetchall():
                user_info = {
                    'username': res['username'],
                    'firstname': res['firstname'],
                    'lastname': res['lastname'],
                    'email': res['email'],
                    'date': res['date'],
                    'uuid': res['uuid']
                }
                users_info.append(user_info)
        return users_info

    def error_response(self, message):
        """Utility function to send an error response"""
        self.write({
            'action': 'login',
            'status': 'failed',
            'message': message
        })

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
    (f"/{base_url}/sign_auth", SignAuth),
    (f"/{base_url}/version", VersionHandler),
    (f"/{base_url}/admin", AdminHandler),
    (f"/{base_url}/files", ListHandler),
    (f"/{base_url}/delete", DeleteHandler),
    (f"/{base_url}/createuser", CreateUserHandler),
    (f"/{base_url}/signpolicy", SignHandler),
    (f"/{base_url}/login", LoginHandler),
    (f"/{base_url}/(.*)", tornado.web.StaticFileHandler, dict(path=root))
])

ec2t = threading.Thread(target=s3thread, args=(awsid, key, fileage, bucketname, ))
ec2t.start()

if __name__ == "__main__":
    application.listen(5000)
    tornado.ioloop.IOLoop.instance().start()
