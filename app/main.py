from flask import render_template, redirect, url_for, request
from app import webapp
import boto3, botocore
from boto3.dynamodb.types import Binary
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto import Random
import base64

@webapp.route('/',methods=['GET','POST'])
def main():

    return render_template("main.html",title="TSNotes")

@webapp.route('/encrypt',methods=['POST'])
def encrypt():
    # Process form data
    message = request.form.get('message',"")
    pw = request.form.get('password',"")

    # Crypto initialization
    salt = rng.read(16) # Salt for pbkdf2
    iv = rng.read(16) # IV for AES
    nonce = rng.read(16) # Nonce to know if decrypted properly

    key = PBKDF2(pw,salt,count=5000,prf = HMAC_SHA256)
    stream = AES.new(key,AES.MODE_CFB,iv)
    msg_enc = stream.encrypt(message)
    nonce_enc = stream.encrypt(nonce)

    print "Key =", base64.urlsafe_b64encode(key)
    print "IV =", base64.urlsafe_b64encode(iv)
    print "ciphertext =", base64.urlsafe_b64encode(msg_enc)

    table = dynamodb.Table('TSNotes')
    db_item = {'salt':Binary(salt),'iv':Binary(iv),'nonce':Binary(nonce),'nonce_enc':Binary(nonce_enc),'message':Binary(msg_enc)}
    while True:
        try:
            msg_id = base64.urlsafe_b64encode(rng.read(15))
            db_item['msg_id'] = msg_id
            response = table.put_item(Item=db_item,ConditionExpression="attribute_not_exists(msg_id)")
            break
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] != 'ConditionalCheckFailedException':
                raise

    return url_for('show',msg_id=msg_id,_external=True)

@webapp.route('/show/<string:msg_id>')
def show(msg_id):
    if (msg_id == ""):
        return "Msg not found."

    table = dynamodb.Table('TSNotes')
    response = table.get_item(Key={'msg_id':msg_id},ConsistentRead=True)

    if 'Item' not in response:
        return "Msg not found."
    return render_template("show.html",title="TSNotes",msg_id=msg_id)
    
@webapp.route('/decrypt',methods=['POST'])
def decrypt():
    msg_id = request.form.get('msg_id',"")
    pw = request.form.get('password',None)
    if (msg_id == ""):
        return "Msg not found."
    if pw is None:
        return "No password given."

    table = dynamodb.Table('TSNotes')
    response = table.get_item(Key={'msg_id':msg_id},ConsistentRead=True)

    if 'Item' not in response:
        return "Msg not found."

    msg = response['Item']
    print msg
    key = PBKDF2(pw,str(msg['salt']),count=5000,prf = HMAC_SHA256)
    stream = AES.new(key,AES.MODE_CFB,str(msg['iv']))
    decrypted = stream.decrypt(str(msg['message']))
    decrypted_nonce = stream.decrypt(str(msg['nonce_enc']))

    if decrypted_nonce != msg['nonce']:
        return "Wrong password."

    return decrypted

# Used to pass into PBKDF2
def HMAC_SHA256(p,s):
    return HMAC.new(p,s,SHA256).digest()


rng = Random.new()
db = {}
#dynamodb = boto3.resource('dynamodb',region_name='us-east-1',endpoint_url="http://localhost:8000")
dynamodb = boto3.resource('dynamodb',region_name='us-east-1')
