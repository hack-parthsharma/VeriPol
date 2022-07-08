#!/usr/bin/python
# Quick key management solution.

from sqlalchemy import create_engine, MetaData, select, and_, Column, func, or_, desc, delete, Table, String, Boolean, Integer, Text
from validate_email import validate_email
from flask import Flask, jsonify, request, make_response
from uuid import uuid4
import logging
from ecdsa import SigningKey, VerifyingKey, BadSignatureError
from base64 import b64encode, b64decode
import json
from mailer import *
import ConfigParser

configFile = 'config.ini'

#Read the config file
Config = ConfigParser.ConfigParser()
Config.read(configFile)
db_string = Config.get("database", "dbms")
server_hostname = Config.get("webserver", "host")
server_port = Config.getint("webserver", "port")
DEBUG = Config.getboolean("email", "debug")

if DEBUG: #Debug mode for server errors, and won't dispatch emails (just print to server console)
    print "WARNING: Running in debug mode, emails won't be dispatched (just printed to console) and server will give verbose errors."

app = Flask(__name__)
dbms = db_string

db = create_engine(dbms)
metadata = MetaData(db)

keyTblDef = Table('keys' , metadata,
            Column('id', Integer, primary_key=True, autoincrement=True),
            Column('user', Text), #E.g. email, but also phone number etc
            Column('publicKey', String(400)),
            Column('verified', Boolean, default=False),
            Column('enabled', Boolean, default=False),
            Column('verifyCode', String(200))
            )

#if 'keys' not in metadata.tables.keys(): #Depending on version of sqlalchemy
if not db.has_table("keys"):
    keyTblDef.create()

metadata.reflect()
t_Keys = metadata.tables['keys']


def unpackCert(cert):
    return (json.loads(b64decode(cert)))

def verifyPublicCert(cert):
    assert cert
    pk = unpackCert(cert)
    msgBody = pk.get("identity") + pk.get("issued") + pk.get("version") + pk.get("publicKey")
    pubKey = VerifyingKey.from_pem(b64decode(pk.get("publicKey")))
    sig = b64decode(pk.get("signature"))
    return pubKey.verify(sig, msgBody)


def dispatchVerifyEmail(email,vuuid,msg=0):
    if msg == 0:
        msg = """Dear User,\n\nPlease verify your identity by clicking this link:\n\nhttp://%s:%d/verify/enable/%s\n\nThank you,\nVeriPol""" % (server_hostname, server_port, vuuid)
    elif msg == 1:
        msg = """Dear User,\n\nPlease verify your identity TO DISABLE YOUR KEY by clicking this link:\n\nhttp://%s:%d/verify/disable/%s\n\nThank you,\nVeriPol""" % (server_hostname, server_port, vuuid)
    if DEBUG:
        print msg
    else:
        result = dispatchemail(email, "Verify your email address", msg)
        if not result:
            print "Failed to dispatch email."


@app.route('/uploadNewKey', methods=['POST'])
def uploadkey():
    if (not request.form.get("pubkey")): #or (not request.form.get("pubkey")):
        return jsonify({"status" : "error", "reason" : "email or pubkey not supplied"})
    #email = request.form['email']
    pubKey = request.form['pubkey']
    if not verifyPublicCert(pubKey):
        return jsonify({"status" : "error", "reason" : "Unable to validate cert authenticity."})
    email = unpackCert(pubKey).get("identity")
    vuuid = str(uuid4())
    t_Keys.insert().execute(user=email,publicKey=pubKey, verifyCode=vuuid)
    dispatchVerifyEmail(email, vuuid)
    return jsonify({"status" : "success"})

@app.route('/verify/<operation>/<vuuid>') #operation = enable or disable
def verifyEmail(operation,vuuid):
    print vuuid
    r = db.execute(select([t_Keys.c.verifyCode], and_(t_Keys.c.verifyCode == vuuid))).fetchone() #, t_Keys.c.verified == False for enable
    if (not r) or (len(r) <= 0):
        return jsonify({"status" : "error", "reason" : "Bad or expired verififcation code."})
    setEnabledTo = True
    if operation == "disable":
        setEnabledTo = False
    u = db.execute(t_Keys.update().where(t_Keys.c.verifyCode == vuuid).values(verified = True, enabled = setEnabledTo, verifyCode = str(uuid4())))
    return jsonify({"status" : "success"})

@app.route('/disableKey', methods=['POST'])
def disableKey():
    if not request.form.get("pubkey"):
        return jsonify({"status" : "error", "reason" : "pubkey not supplied"})
    pubKey = request.form['pubkey']
    vuuid = str(uuid4())
    u = db.execute(t_Keys.update().where(t_Keys.c.publicKey == pubKey).values(verifyCode = vuuid)) #Set random verify
    if u.rowcount <= 0:
        print("Warning: Bad Public Key submitted for disabling: %s " % str(pubKey))
    else:
        r = db.execute(select([t_Keys.c.user]).where(t_Keys.c.verifyCode == vuuid)).fetchone()
        if (not r) or (len(r) <= 0):
            return jsonify({"status" : "error"})
        email = r[0]
        dispatchVerifyEmail(email,vuuid,1)
    return jsonify({"status" : "success"})


@app.route('/getPublicKey/<userID>')
def getPublicKey(userID):
    r = db.execute(select([t_Keys.c.publicKey], and_(t_Keys.c.user == userID, t_Keys.c.verified == True, t_Keys.c.enabled == True))).fetchall()
#    if len(r) < 1:
#        return jsonify({"status" : "error", "reason" : "No public key for user."})
    entries = []
    for x in r:
        entries.append(x[0])
    return jsonify({"status" : "success", "keys" : entries})


if __name__ == '__main__':
    numKeys = db.execute(func.count(t_Keys.c.user)).fetchone()[0]
    print "[+] Starting key server with '%d' keys in database..." % numKeys
    app.run(host="0.0.0.0", port=server_port, debug=DEBUG)
