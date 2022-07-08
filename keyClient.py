#!/usr/bin/env python
# Quick key management solution - client
# Todo:
#   [ ] Replace prints with logging messages
#   [ ] Add expiration date to keys
#   [ ] Add 'type' to identifier (email, phone, Twitter, etc). Server will need to dispatch message to these.
#   [ ] Add ability to disable cert. Mark as disabled on server, after clicking verification link.

from ecdsa import SigningKey, VerifyingKey, BadSignatureError, NIST192p #,  NIST384p, SECP256k1
import ecdsa.curves
import argparse
import requests
import datetime
from base64 import b64encode, b64decode
import json
import os.path

version = "1.0"
#curve=NIST384p

def uploadPubCert(cert, host):
    data = {"pubkey" : cert}
    r = requests.post(host + "/uploadNewKey", data)
    if r.status_code == 200:
        rj = json.loads(r.text)
        if rj.get("status") == "success":
            return True
    return False

def signMessage(msg, pKeyFile="private.pem"):
    """Sign message with private key"""
    assert os.path.isfile(pKeyFile)
    assert msg
    privKey = SigningKey.from_pem(open(pKeyFile).read())
    sig = privKey.sign(msg)
    sig = b64encode(sig)
    return sig

def verifyMessage(msg, cert, sig):
    """Verify message agasint cert"""
    #First validate the cert
    if not verifyPublicCert(cert):
        return False
    try:
        pk = json.loads(b64decode(cert))
        pubKey = VerifyingKey.from_pem(b64decode(pk.get("publicKey")))
        sig = b64decode(sig)
    except:
        return False
    return pubKey.verify(sig, msg)

def verifySignedMessage(sigmsg, keyserver):
    f = open(sigmsg,"rb").read()
    m = json.loads(f)
    msg = m.get("message")
    frm = m.get("from")
    sig = m.get("signature")
    r = requests.get(keyserver + "/getPublicKey/" + frm)
    if r.status_code == 404:
        print "[!] No public keys for '%s' on keyserver '%s'" %(frm, keyserver)
        return False
    rj = json.loads(r.text)
    keys = rj.get("keys")
    if len(keys) < 1:
        print "[!] No verified public keys for '%s' on keyserver '%s'" %(frm, keyserver)
        return False
    for k in keys:
        try:
            if verifyMessage(msg, k, sig):
                print "[+] Message validated to be from '%s'" % frm
            return True
        except:
            pass
    return False

def unpackCert(cert):
    return (json.loads(b64decode(cert)))

def verifyPublicCert(cert):
    assert cert
    pk = unpackCert(cert)
    msgBody = pk.get("identity") + pk.get("issued") + pk.get("version") + pk.get("publicKey")
    pubKey = VerifyingKey.from_pem(b64decode(pk.get("publicKey")))
    sig = b64decode(pk.get("signature"))
    return pubKey.verify(sig, msgBody)

def generateKeyPair(identity,_curve=NIST192p):
    assert identity
    if os.path.isfile("private.pem") or os.path.isfile("public.pem") or os.path.isfile("publicCert.txt"):
        print "Error keyfiles already exists"
        exit(-1)
    privateKey = SigningKey.generate(curve=_curve) # default NIST192p
    publicKey = privateKey.get_verifying_key()
    privateKey_txt = privateKey.to_pem()
    publicKey_txt = publicKey.to_pem()
    now = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d %H:%M:%S')
    pk = {
        "identity" : identity,
        "curve": _curve.name,
        "issued" : now,
        "version" : version,
        "publicKey" : b64encode(publicKey_txt)
    }
    msgBody = pk.get("identity") + pk.get("issued") + pk.get("version") + pk.get("publicKey")
    sig = b64encode(privateKey.sign(msgBody))
    pk["signature"] = sig
    pk = b64encode(json.dumps(pk))
    open("private.pem","w").write(privateKey_txt)
    open("public.pem","w").write(publicKey_txt)
    open("publicCert.txt","w").write(pk)
    #return pk


def main():
    parser = argparse.ArgumentParser(description='Key signing tool')
    parser.add_argument('-g', '--generatekeypair', help="Supply identity to generate keypair for (e.g. email, phone number)")
    parser.add_argument('-s', '--sign', help="Sign message with private key. Supply message.")
    #parser.add_argument('-m', '--message', help="Message file.")
    #parser.add_argument('-f', '--sigfile', help="Signature file.")
    #parser.add_argument('-p', '--publiccertfile', help="Public certificate file for verification purposes.")
    parser.add_argument('-v', '--verify', help="Verify message. Supply signed message file.")
    parser.add_argument('-u', '--uploadpublickey', help="Upload public key to server. Specify full server address.")
    parser.add_argument('-x', '--keyserver', help="Key server for validation and sync of keys.")
    parser.add_argument('-l', '--listcurves', help="List available curves", action='store_true')
    parser.add_argument('-c', '--curve', help="Curve to use. Default is to use NIST192p.", default='NIST192p')

    args = parser.parse_args()
    if args.listcurves:
        print "[+] Available curves:\n"
        for cc in ecdsa.curves.curves:
            print "\t" + cc.name + "\t(" + cc.openssl_name + ")"
    if args.generatekeypair:
        curves = {}
        for cc in ecdsa.curves.curves:
                curves[cc.name] = cc
        curve = curves.get(args.curve)
        print "[+] Generating keypair for '%s' with '%s' curve" % (args.generatekeypair, args.curve)
        generateKeyPair(args.generatekeypair,_curve=curve)
    elif args.sign:
        if not os.path.isfile("private.pem"):
            print "[!] Error: Unable to load 'private.pem'. Have you generated your keys?"
            exit(-1)
        message = open(args.sign,"rb").read()
        print "[-] Signing '%s'..." % args.sign
        sig = signMessage(message)
        cert = unpackCert(open("publicCert.txt","rb").read())
        sender = cert.get("identity")
        signedMessage = json.dumps({"from" : sender, "message" : message, "signature" : sig}, indent=4)
        open(args.sign + "-signed","wb").write(signedMessage)
        print "[+] Created signed message " + args.sign + "-signed"
    elif args.verify:
        if not args.keyserver:
            print "[!] Error: Please supply keyserver option for validation."
            exit(-1)
        if not verifySignedMessage(args.verify, args.keyserver):
            print "[!] Unable to verify message. Don't trust it."
            exit(-1)
    if args.uploadpublickey:
        if not os.path.isfile("publicCert.txt"):
            print "[!] Error, cannot open 'publicCert.txt'"
            exit(-1)
        cert = open("publicCert.txt","rb").read()
        if uploadPubCert(cert, args.uploadpublickey):
            print "[+] Public cert uploaded!"
        else:
            print "[!] Could not upload cert :("

if __name__ == "__main__":
    main()
