# VeriPol
This is a small project exploring message signing and key distribution. Key creation and message signing is done using ECDSA cryptography (Elliptic Curve Digital Signature Algorithm) with the excellent [Pure-Python ECDSA](https://github.com/warner/python-ecdsa) package.

As this is a PoC / learning exercise:

* Do *not* use this code in production; assume it's unsafe.
* Do file issues to help us all learn about crypto.

## Usage
### 1. Server Setup
First a key server needs to be running, this can be done via:
```
$ python keyServer.py
[+] Starting key server with '0' keys in database...
 * Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)
```


### 2. Alice creates and uploads her keys
Alice creates a keypair with her unique identifier (say, email address):
```
$ python keyClient.py -g alice@net.com
[+] Generating keypair for 'alice@net.com'
```

She uploads this to our previously created key server:
```
$ python keyClient.py -u http://1.2.3.4:5000
[+] Public cert uploaded!
```

The server will email her a link to prove she owns this email address. Her public key cannot be used until she clicks this link. e.g:
```
Dear User,
Please verify your identity by clicking this link:
http://1.2.3.4:5000/verify/enable/eeb059ef-b6c1-41a1-8ff5-98294ad4e1e1
```

(Note: in debug mode the webserver will just output this link to the terminal)

### 3. Alice signs a message and sends it to Bob
She creates and signs a message:
```
$ echo "Hey Bob, meet me at the park at 3pm to discuss our plan." > message.txt
$ python keyClient.py -s message.txt
[-] Signing 'message.txt'...
[+] Created signed message message.txt-signed
```
This creates a file called message-signed.txt which can be delivered to Bob.
```
cat message.txt-signed
{
    "message": "Hey Bob, meet me at the park at 3pm to discuss our plan.\n",
    "from": "alice@net.com",
    "signature": "v1sNTDXsctFmwmSTWKuX9yEHPGaTPnoBBkJYYJ3Epx3/GEVzFtgDQOq/lHAycDsY"
}
```

### 4. Bob receives the message and validates
```
python keyClient.py -v message.txt-signed -x http://1.2.3.4:5000
[+] Message validated to be from 'alice@net.com'
```

## UML Diagrams
The above can be illustrated in the following diagrams

### 1. Alice creates public and private keys, and uploads her public certificate
![alt text](AliceCreates.png)
### 2. Alice creates and signs a message, sending it to Bob who verifies it
![alt text](BobVerifies.png)

# Configuration file

The 'config.ini' configuration file is used to specify server side variables relating to database storage and email settings (SMTP / AWS). An example configuration file is below:

```
[database]
dbms = sqlite:///keyStore.db

[webserver]
host = myserver.com
port = 5000

[email]
sender_name = VeriPol Key Server
sender_email = verifyme@gmail.com
mode = smtp
debug = True

[smtp_settings]
server = smtp.gmail.com
port = 465
ssl = True
user = verifyme@gmail.com
password = qbzunfnavprohz.rot13

[amazon_aws]
AWS_ACCESS_KEY = ZG9tc2JlYXJkaXNmaWVyY2U=
AWS_SECRET_KEY = YnV0Y2hyaXNiZWFyZGlzYmV0dGVy
AWS_REGION = us-west-2
```

If the 'debug' property is True email will not be dispatched, but only printed to the server console.
The 'mode' property can be either "smtp" or "aws" (this will be ignored if we're in debug mode).
Any valid sqlalchemy dbms strings are accepted e.g:
 * postgresql://user:password@server:5432/somedb
 * mysql://user:password@server:3306/somedb
 * sqlite:///keyStore.db

# Appendix

## Key Format
Public and private keys are generated, and a 'certificate' of sorts is created and signed with the private key. This ensures your chosen identity is bound to the public key.

```
{  
   "issued" : "2017-07-28 18:03:45",
   "curve" : "NIST384p",
   "publicKey" : "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUU1eXpJQmQwZjdTNkhwc2ZTa2hXS1RxNVJjNjA0VUtVaQp3MUl5Q21BT0Foc3JESndJWVlyVTBsdTJSVUxxMUNUd0lwMG1UbmNPYlpKdi9OSGFjL3R1Y0xMS0gveU5Md3lnCk81amgzalFOMEZxV1pBM1NEbTFtTVJwVmo0NFpQMHZnCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=",
   "version" : "1.0",
   "signature" : "fiSQu8iWebvOukGKmgojdLT7wFOqmMMVmh7LKBUqBt6rQaqMzkh2g1Gp/iZFaGg54jlIJenRpNfCWkpWSgpBbCJzTz8Jlgaet6nNwoGrNgaWZi7pZ35fNlbS0wT3KZEL",
   "identity" : "glennzw@protonmail.com"
}
```

The algorithm behind the signature property above is:
```
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
print pk #Gives the above output
```

## RSA vs Elliptic Curves
This project uses Elliptic Curves for signing messages. Specifically, we use [Pure-Python ECDSA](https://github.com/warner/python-ecdsa); an easy-to-use implementation of ECDSA cryptography (Elliptic Curve Digital Signature Algorithm).

Public-key cryptography is based on the intractability of certain mathematical problems. Your typical PGP solutions work by assuming that it is difficult to factor a large integer composed of two or more large prime factors (e.g. RSA). Rather than large primes, elliptic-curve-based protocols assume that finding the discrete logarithm of a random elliptic curve element with respect to a publicly known base point is infeasible (the "elliptic curve discrete logarithm problem" (ECDLP)).

The primary benefit of ECC is a smaller key size. For example, a 256-bit elliptic curve public key should provide comparable security to a 3072-bit RSA public key.

![alt text](keySizes.jpg)

By default we use NIST192p (prime192v1 in OpenSSL) when creating keys, but alternative curves can be specified with the --curve (-c) flag. All available curves can be listed with --listcurves (-l).

```
python keyClient.py -l
[+] Available curves:

	NIST192p	(prime192v1)
	NIST224p	(secp224r1)
	NIST256p	(prime256v1)
	NIST384p	(secp384r1)
	NIST521p	(secp521r1)
	SECP256k1	(secp256k1)

python keyClient.py -g glennzw@fbi.gov -c NIST521p
[+] Generating keypair for 'glennzw@protonmail.com' with 'NIST521p' curve

```

## ToDo:
 * Add support for dispatching SMSs to verify identity of phone numbers (ZenSend).
 * Add support for SendGrid email dispatching.
 * Add a Web UI for the server.
 * Use proper Python logging output.
 * Add ability to run web server within Apache/nginx/etc.
 * Add text customization for verification email/sms.
 * Add support for multiple keys/identities.
 * Add encryption. ECDSA is typically a signature algorithm; so possibly create a separate key.


## Other projects
[KeyBase](https://keybase.io) - Has a nice API, but currently in Alpha / invite only. Also only the client (not server) is open source.  
[SKS PGP Server](https://bitbucket.org/skskeyserver/sks-keyserver/overview) - Run your own PGP server


## References
https://github.com/crypto101/crypto101.github.io/raw/master/Crypto101.pdf  
https://www.youtube.com/watch?v=yBr3Q6xiTw4  
https://www.youtube.com/watch?v=y_YxRUTI-xU  
https://arstechnica.com/information-technology/2013/10/a-relatively-easy-to-understand-primer-on-elliptic-curve-cryptography/  
https://www.globalsign.com/en/blog/elliptic-curve-cryptography/  
https://en.wikipedia.org/wiki/Elliptic_curve_cryptography  
https://en.wikipedia.org/wiki/RSA_(cryptosystem)  
