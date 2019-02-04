import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
domain = "127.0.0.1"
def send_email(to, subject, text): 
    fromaddr = "homeworksmailbot@gmail.com"
    toaddr = to
    msg = MIMEMultipart()
    msg['From'] = fromaddr
    msg['To'] = toaddr
    msg['Subject'] = subject
 
    body = text
    msg.attach(MIMEText(body, 'plain'))
 
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(fromaddr, "mithereicome@91")
    text = msg.as_string()
    server.sendmail(fromaddr, toaddr, text)
    server.quit()

def send_confirmation_email(user_email,user_name, confirmation_key):
    send_email(user_email, "Welcome to HomeWorks by Dewan!",
"""Hello {}!, and thanks for registering with {}!
We are really happy that you choose to be a part of our site

Please click the below link to confirm your email with us:

{}/confirm_email_link/{}/

Once you've done that, your account will be enabled, and you will be able to access everything that is available with us

If you didn't register an account, then you can disregard this email.

Regards
Rajat Tomar
Founder & Creator
(rajattomar1301@gmail.com)""".format(user_name,"HomeWorks By Dewan",domain , confirmation_key))


def send_new_homework_email(user_email, user_name, teacher_name, subject, deadline):
    send_email(user_email, "New HomeWork By {}".format(teacher_name), 
        """Hey {} 
I know this is probably bad news for ya but your {} teacher gave you a new homework to do.
It's due by {} so you better hurry fella!

It was awesome talking to you!
Happy Homeworking!

Regards
Rajat Tomar
System Admin and Creator
(rajattomar1301@gmail.com)""".format(user_name, subject, deadline))


def send_welcome_email(user_email, user_name, provider):
    send_email(user_email, "Welcome To HomeWorks By Dewan", 
        """Hey {} 
I would like to take the opportunity of thanking you for signing up on our platform using your {} credentials.
There are a lot of things for you to explore so I suggest you get right on them :)
Once again welcome aboard sailor!

It was awesome talking to you!
Happy Homeworking!

Regards
Rajat Tomar
System Admin and Creator
(rajattomar1301@gmail.com)""".format(user_name, provider))

def send_query_email(name, email, phone, regard, query):
    send_email("rajattomar1301@gmail.com", "New query from {}".format(name),"""Hey Rajat,
You have a new query from {} their email id is: {} and phone number is: {}
It's reagarding {} and they say:
{}

Thanks!

""".format(name, email, phone, regard, query))

def send_reset_email(email, name, conf_key):
    send_email(email, "You requested for a new password!","""
Hey {}!
We see that you requested for your password to be changed!
Please click the below link for changing your password:
{}/reset-password-page/{}/{}/


Please note that the above link is valid only for one time use""".format(name,domain,email, conf_key))


def is_valid_email(email):

	if len(email) > 7:
		if re.match("^.+\\@(\\[?)[a-zA-Z0-9\\-\\.]+\\.([a-zA-Z]{2,3}|[0-9]{1,3})(\\]?)$", email) != None:
			return 1
	return 0
