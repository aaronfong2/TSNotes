from flask import render_template, redirect, url_for, request
from app import webapp
import boto3
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
    salt = rng.read(16) # Salt for pbkdf2
    iv = rng.read(16) # IV for AES
    nonce = rng.read(16) # Nonce to know if decrypted properly
    #print request.url
    #print base64.urlsafe_b64encode(rng.read(100))

    key = PBKDF2(pw,salt,count=5000,prf = HMAC_SHA256)
    stream = AES.new(key,AES.MODE_CFB,iv)
    encrypted = stream.encrypt(message)
    encrypted_nonce = stream.encrypt(nonce)

    print "Key =", base64.urlsafe_b64encode(key)
    print "IV =", base64.urlsafe_b64encode(iv)
    print "ciphertext =", base64.urlsafe_b64encode(encrypted)

    msg_id = base64.urlsafe_b64encode(rng.read(15))
    db[msg_id] = {'salt':salt,'iv':iv,'nonce':nonce,'nonce_enc':encrypted_nonce,'message':encrypted}
    return msg_id

@webapp.route('/show',methods=['GET','POST'])
def show():
    msg_id = request.args.get('msg_id',"")
    if (msg_id == "" or msg_id not in db):
        return "Msg not found."
    return render_template("show.html",title="TSNotes",msg_id=msg_id)
    
@webapp.route('/decrypt',methods=['POST'])
def decrypt():
    msg_id = request.form.get('msg_id',"")
    pw = request.form.get('password',None)
    if (msg_id == "" or msg_id not in db):
        return "Msg not found."
    if pw is None:
        return "No password given."

    msg = db[msg_id]
    key = PBKDF2(pw,msg['salt'],count=5000,prf = HMAC_SHA256)
    stream = AES.new(key,AES.MODE_CFB,msg['iv'])
    decrypted = stream.decrypt(msg['message'])
    decrypted_nonce = stream.decrypt(msg['nonce_enc'])

    if decrypted_nonce != msg['nonce']:
        return "Wrong password."

    return decrypted

# Used to pass into PBKDF2
def HMAC_SHA256(p,s):
    return HMAC.new(p,s,SHA256).digest()


rng = Random.new()
db = {}
