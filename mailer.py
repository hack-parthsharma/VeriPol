#!/usr/env/python
# Handle dispatching mail via SMTP or AWS
import ConfigParser

configFile = 'config.ini'

#Read the config file
Config = ConfigParser.ConfigParser()
Config.read(configFile)

#email
sender_name = Config.get("email", "sender_name")
sender_email = Config.get("email", "sender_email")
mode = Config.get("email", "mode")

if mode == "smtp":
    #SMTP settings
    smtp_server = Config.get("smtp_settings", "server")
    smtp_port = Config.get("smtp_settings", "port")
    smtp_ssl = Config.getboolean("smtp_settings", "ssl")
    smtp_user = Config.get("smtp_settings", "user")
    smtp_password = Config.get("smtp_settings", "password")
elif mode == "aws":
    #AWS settings
    AWS_ACCESS_KEY = Config.get("amazon_aws","AWS_ACCESS_KEY")
    AWS_SECRET_KEY = Config.get("amazon_aws","AWS_SECRET_KEY")
    AWS_REGION = Config.get("amazon_aws", "AWS_REGION")
else:
    print "Bad 'mode' setting in config file. Available options: smtp or aws"

def dispatchemail(recipient, subject, body):
    if mode == "smtp":
        return send_smtp(recipient, subject, body)
    elif mode == "aws":
        return amazon_mail(recipient, subject, body)

def amazon_mail(recipient, subject, body):
    import boto.ses
    conn = boto.ses.connect_to_region(AWS_REGION,aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY)
    try:
        r = conn.send_email(sender_email, subject, None, recipient,format='text',text_body=body)
    except Exception, e:
        print "Unable to send email to %s" % recipient
        print e
        return False
    else:
        return True

def send_smtp(recipient, subject, body):
    import smtplib
    TO = recipient if type(recipient) is list else [recipient]
    # Prepare actual message
    message = """From: %s\nTo: %s\nSubject: %s\n\n%s
    """ % (sender_email, ", ".join(TO), subject, body)
    try:
        if smtp_ssl:
            server = smtplib.SMTP_SSL(smtp_server, smtp_port)
            server.ehlo() # optional, called by login()
        else:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.ehlo()
            server.starttls()
        server.login(smtp_user, smtp_password)
        server.sendmail(sender_email, recipient, message)
        server.close()
        print "Sent email to %s" % recipient
        return True
    except Exception, e:
        print "Unable to send email to %s" % recipient
        print e
        return False
