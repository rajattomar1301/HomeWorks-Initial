from flask import Flask, render_template, session, redirect, url_for, request, g, flash, jsonify, send_from_directory
app = Flask(__name__)
from database import *
from hashlib import sha512
from utils import misc, emails, decorators
from datetime import datetime
from peewee import fn 
import requests
import socket
import os
from datetime import datetime
from flask_oauth import OAuth

oauth = OAuth()
#============FACEBOOK CREDENTIALS=============
FACEBOOK_APP_ID = '779154038943789'
FACEBOOK_APP_SECRET = 'c89750e663308fd15a96771414bcf4b5'
facebook = oauth.remote_app('facebook',
    base_url='https://graph.facebook.com/',
    request_token_url=None,
    access_token_url='/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    consumer_key=FACEBOOK_APP_ID,
    consumer_secret=FACEBOOK_APP_SECRET,
    request_token_params={'scope': 'email'}
)


#============GOOGLE CREDENTIALS===============
GOOGLE_CLIENT_ID = '965424219586-0q991bb1c8g937pttp0s7dgkbp3i2hf3.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = 'fl4frGoup3CYhvDXlC815J6-'
REDIRECT_URI = '/oauth2callback'  # one of the Redirect URIs from Google APIs console
google = oauth.remote_app('google',
                          base_url='https://www.google.com/accounts/',
                          authorize_url='https://accounts.google.com/o/oauth2/auth',
                          request_token_url=None,
                          request_token_params={'scope': 'https://www.googleapis.com/auth/userinfo.email',
                                                'response_type': 'code'},
                          access_token_url='https://accounts.google.com/o/oauth2/token',
                          access_token_method='POST',
                          access_token_params={'grant_type': 'authorization_code'},
                          consumer_key=GOOGLE_CLIENT_ID,
                          consumer_secret=GOOGLE_CLIENT_SECRET)


app.secret_key = "mithereicome@91"

import logging
logging.basicConfig(level=logging.DEBUG)

@app.before_request
def make_info_available():
    if "user_id" in session:
        g.user = User.get(User.id == session["user_id"])

@app.context_processor
def scoreboard_variables():
    var = dict()
    if "user_id" in session:
        var["logged_in"] = True
        var["user"] = g.user
    else:
        var["logged_in"] = False

    return var


@app.route('/')
def root():
	if "user_id" in session:
		return redirect(url_for('dashboard'))

	else:
		return render_template('index.html')


@app.route('/send-contact-email/', methods=["POST"])
def sendcontactemail():
	if request.method == "POST":
		name = request.form['name'].strip()
		email = request.form['email'].strip()
		phone = request.form['phone'].strip()
		regard = request.form['regard'].strip()
		query = request.form['query'].strip()
	try:
		emails.send_query_email(name,email,phone,regard,query)
		flash("Your Query has been sent!")
		return redirect(url_for("root"))
	except:
		flash("There was an error in sending the email")
		return redirect(url_for("root"))

@app.route('/register/', methods=["GET", "POST"] )
def register():
	if request.method == "GET":
		return render_template('register.html')

	elif request.method == "POST":
		name = request.form['name'].strip()
		email = request.form['email'].strip()
		password = request.form['password'].strip()
		isAteacher = "teacher" in request.form
		standard = request.form["standard"].strip()
		section = request.form['section'].strip()
		school = request.form['school'].strip()
		key = misc.generate_confirmation_key()

		if not name:
			flash("Please enter a name smarty!")
			return render_template("register.html")

		if not email:
			flash("A valid email id would be appreciated!")
			return render_template("register.html")

		if not password or len(password) < 8:
			flash("Please select a password more than 8 characters!")
			return render_template("register.html")

		if not isAteacher:
			isAteacher = False

		if not standard:
			flash("Please select a standard!")
			return render_template('register.html')

		if not section or len(section) > 1:
			flash("Please enter a valid section!")
			return render_template('register.html')

		if not school:
			flash("Please enter a valid school matey!")
			return render_template('register.html')
		try:
			user = User.get(User.email == email)
			flash("A user with this email id already exsists please login using your credentials")
			return redirect(url_for('login'))

		except User.DoesNotExist:

			try:
				user = User.create(name=name , email=email , password = sha512(password).hexdigest() , isATeacher = isAteacher, standard=str(standard), section=section, school = school , conf_key = key, firstsociallogin = False)
				emails.send_confirmation_email(email, name , key)
				session['user_id'] = user.id
				flash("Ahoy! You're registered!")
				return redirect(url_for('dashboard'))
			
			except:

				return "There was an error in the system <br> Please contact the administrator with the details of the problem at rajattomar1301@gmail.com"

@app.route('/login/', methods=["GET", "POST"])
def login():
	if "user_id" in session:
		return redirect(url_for('dashboard'))

	if request.method == "GET":
		return render_template("login.html")

	elif request.method == "POST":
		user_email = request.form['email'].strip()
		password = request.form['password'].strip()
		try:
	 		user = User.get(User.email == str(user_email) )
	 		if user.password == sha512(password).hexdigest():
	 			flash("Ahoy you're in eh!")
	 			session["user_id"] = user.id
	 			return redirect(url_for('dashboard'))
	 		else:
	 			flash("Wrong Password there buddy!")
	 			return render_template("login.html")
	 	except:
	 		flash("User not found buddy!")
	 		return render_template("login.html")


@app.route('/dashboard/', methods=["GET"])
@decorators.login_required
@decorators.data_required
def dashboard():
	if request.method == "GET":
		return render_template('dashboard.html')

@app.route('/update-details/', methods=["POST"])
@decorators.login_required
def update_details():
	email = request.form['email'].strip()
	standard = request.form['standard'].strip()
	section = request.form['section'].strip()
	school = request.form['school'].strip()

	if email != "" and emails.is_valid_email(email) and g.user.email != email :
		g.user.email = email
		g.user.emailconf = False
		confkey = misc.generate_confirmation_key()
		g.user.conf_key = confkey
		emails.send_confirmation_email(g.user.email, g.user.name, confkey)
		g.user.save()
		flash("Email changed!")
	if standard != "" and g.user.standard != standard:
		g.user.standard = standard
		g.user.save()
		flash("standard changed!")

	if section != "" and g.user.section != section:
		g.user.section = section
		g.user.save()
		flash("Section changed!")
	if school != "" and g.user.school != school:
		g.user.school = school
		g.user.save()
		flash("School name changed")
			
	return redirect(url_for('dashboard'))


@app.route('/confirm_email_link/<confirmation_key>/', methods=["GET"])
@decorators.login_required
def confirm_email_link(confirmation_key):
    if confirmation_key == g.user.conf_key:
        flash("Email confirmed!")
        g.user.emailconf = True
        g.user.save()
    else:
        flash("Email Not Verified.")
    return redirect(url_for('dashboard'))

@app.route('/teacher-homework/', methods=["GET", "POST"])
@decorators.login_required
@decorators.teacher_required
@decorators.data_required
def teacher_homework():
	if request.method == "GET":
		return render_template("teacher_homework.html")

	elif request.method == "POST":
		name = request.form['name'].strip()
		description = request.form['description'].strip()
		file = request.files['file']
		deadline = request.form['deadline'].strip()
		meantfor = request.form['meantfor'].strip()
		subject = request.form['subject'].strip()
		filename = generate_name(file.filename)
		author = g.user.name
		meantforsection = request.form['meantforsection'].strip()

		if not name:
			flash("Please enter a name for the homework.")
			return render_template('teacher_homework.html')

		if not description:
			flash("Please enter a homework description")
			return render_template('teacher_homework.html')

		if not file or not allowed_files(file.filename) :
			flash("Please select a valid file! only jpg, jpeg or pdf")
			return render_template("teacher_homework.html")

		if not deadline:
			flash("Please enter the deadline")
			return render_template('teacher_homework.html') 
		if not meantfor:
			flash("Please enter the targeted class")
			return render_template('teacher_homework.html')
		if not subject:
			flash("Please enter a valid subject.")
			return render_template('teacher_homework.html')

		HomeWork.create(name = name , description = description, filename= filename, originalname = file.filename, deadline = deadline, teacher = g.user.id, meantfor = meantfor,meantforsection = meantforsection ,subject = subject, teachername = author)
		for student in User.select().where(User.standard == meantfor and User.section == meantforsection):
			emails.send_new_homework_email(student.email, student.name, author, subject, deadline)
		file.save(os.path.join('homework_files', filename))
		flash("Homework successfully created!")
		return redirect(url_for('dashboard'))
			


@app.route('/teacher-view-homeworks/')
@decorators.login_required
@decorators.teacher_required
@decorators.data_required
def teacher_view_homework():
	homeworks = HomeWork.select().where(HomeWork.teacher == g.user.id)
	return render_template('teacher_view_homework.html', homeworks = homeworks)

@app.route('/teacher-delete-homework/<hid>/')
@decorators.login_required
@decorators.teacher_required
def teacher_delete_homework(hid):
	try:
		hid = int(hid)
		HomeWork.delete().where(HomeWork.id == hid).execute()
		HomeWorkSubmission.delete().where(HomeWorkSubmission.homework == hid).execute()
		Submitted.delete().where(Submitted.homework == hid).execute()
		flash("HomeWork deleted successfully!")
		return redirect(url_for('teacher_view_homework'))
	except:
		flash("There was an error in deleting the homework")
		return redirect(url_for('teacher_view_homework'))

@app.route('/teacher-update-marks/<sid>/<hid>/', methods=["POST"])
@decorators.login_required
@decorators.teacher_required
@decorators.data_required
def teacher_update_marks(sid,hid):
	mark = request.form['marks'].strip()
	h = HomeWorkSubmission.get(HomeWorkSubmission.homework == hid and HomeWorkSubmission.student == sid)
	h.marks = mark
	h.save()
	flash("Marks alloted successfully!")
	return redirect('/teacher-view-students/'+hid+"/")


@app.route('/showfiles/<directory>/<filename>/')
@decorators.login_required
@decorators.data_required
def showfiles(directory, filename):
	if directory == "homework":
		folder = "homework_files"
	else:
		folder = "homework_submission_files"
	return send_from_directory(folder, filename)

@app.route('/teacher-view-students/<homeworkid>/')
@decorators.login_required
@decorators.teacher_required
@decorators.data_required
def teacherviewstudents(homeworkid):
	homework = HomeWork.get( HomeWork.id == homeworkid)
	students = User.raw("select User.id, User.name, User.section, User.standard, h.marks, h.filename1, h.originalfilename1 from User left join HomeWorkSubmission h on User.id = h.student and h.homework="
		+ str(homework.id) +" where User.section='" + homework.meantforsection + "' and User.standard="+homework.meantfor)
	submitted = [x.student for x in Submitted.select().where(Submitted.homework == homeworkid) ]
	return render_template('teacher_view_students.html', students = students, homework = homework, submitted = submitted)

@app.route('/student-view-homeworks/')
@decorators.login_required
@decorators.student_required
@decorators.data_required
def student_view_homework():
	homeworks = HomeWork.select().where(HomeWork.meantfor == g.user.standard and HomeWork.meantforsection == g.user.section)
	submitted = [x.homework for x in Submitted.select().where(Submitted.student == g.user.id)]
	return render_template('student_view_homework.html', homeworks = homeworks, submitted = submitted)


@app.route('/student-view-submitted/')
@decorators.login_required
@decorators.student_required
@decorators.data_required
def student_view_submitted():
	homeworks = HomeWork.raw("select * from HomeWork left join HomeWorkSubmission where HomeWork.id = HomeWorkSubmission.homework and HomeWork.meantforsection ='"+g.user.section+ "' and HomeWork.meantfor="+g.user.standard)
	submitted = [x.student for x in Submitted.select().where(Submitted.student == g.user.id)]
	return render_template('student_view_submitted.html', homeworks = homeworks, submitted = submitted)


@app.route('/student-view-grades/')
@decorators.data_required
@decorators.login_required
@decorators.student_required
def student_view_grades():
	homeworks = HomeWork.raw("select * from HomeWork left join HomeWorkSubmission where HomeWork.id = HomeWorkSubmission.homework and HomeWork.meantforsection ='"+g.user.section+ "' and HomeWork.meantfor="+g.user.standard)
	return render_template('student_view_grades.html', homeworks = homeworks)


@app.route('/student-submit-homework/<homeworkid>/', methods=["POST"])
@decorators.login_required
@decorators.student_required
@decorators.data_required
def student_submit_homework(homeworkid):
	if request.method == "POST":
		file = request.files['filename']
		filename = generate_name(file.filename)

		if not allowed_files(file.filename):
			flash("Please upload a file a allowed file (jpeg/jpg/pdf)")
			return redirect(url_for('student_view_homework'))

		HomeWorkSubmission.create(student = g.user.id, time = str(datetime.now()), marks = 0, filename1 = filename, originalfilename1 = file.filename, homework = homeworkid)
		Submitted.create(homework = homeworkid, student = g.user.id)
		file.save(os.path.join('homework_submission_files', filename))
		flash("The HomeWork was submitted successfully")
		return redirect(url_for('student_view_homework'))



@app.route('/logout/')
def logout():
	session.clear()
	flash("Logout successfully captain!")
	return redirect(url_for('login'))

@app.route('/reset-password/', methods=["GET", "POST"])
def reset_password():
	if "user_id" in session:
		flash("You are already logged in!")
		return redirect(url_for('dashboard'))
	if request.method == "GET":
		return render_template('reset_password.html')

	elif request.method == "POST":
		email = request.form['email'].strip()

	try:
		user = User.get(User.email == email)
		conf_key = misc.generate_confirmation_key()
		user.conf_key = conf_key
		emails.send_reset_email(user.email,user.name, user.conf_key)
		user.save()
		flash("An email with the instructions has been sent to your mail id!")
		return redirect(url_for('reset_password'))

	except User.DoesNotExist:
		flash("No account associated with this email address!")
		return redirect(url_for('reset_password'))

@app.route('/reset-password-page/<email>/<key>/', methods=["GET","POST"])
def reset_password_page(email,key):
	if "user_id" in session:
		flash("You are already logged in!")
		return redirect(url_for('dashboard'))
	if request.method == "GET":
		try:
			user = User.get(User.email == email)
			if user.conf_key == key:
				return render_template("reset_password_set.html", email = user.email , key = key)
			else:
				return "You are using an invalid key"

		except User.DoesNotExist:
			return "Your are using an invalid link!"

	elif request.method == "POST":
		try:
			user = User.get(User.email == email)
			password = request.form['password'].strip()
			if user.conf_key == key:
				user.password = sha512(password).hexdigest()
				user.conf_key = "null"
				user.save()
				flash("Your password has been changed!")
				return redirect(url_for('login'))
			else:
				return "Don't try to fool me!"
		except User.DoesNotExist:
			return "haha! you can't fool me you hacker!"


#Login with facebook
@app.route('/facebook-login/')
def facebook_login():
    return facebook.authorize(callback=url_for('facebook_authorized',
        next=request.args.get('next') or request.referrer or None,
        _external=True))


@app.route('/login/authorized')
@facebook.authorized_handler
def facebook_authorized(resp):
    if resp is None:
    	flash("You denied our website access to your facebook data!")
    	return render_template('login.html')

    session['oauth_token'] = (resp['access_token'], '')
    me = facebook.get('/me?fields=name,email,verified')
    name = me.data['name'].strip()
    email = me.data['email'].strip()
    verified = me.data['verified']
    try:
    	user = User.get(User.email == email)
    	session["user_id"] = user.id
    	if user.firstsociallogin:
    		flash("Please enter all the required details!")
    		return redirect(url_for('first_social'))

    	flash("So you're back using facebook!")
    	return redirect(url_for("dashboard"))

    except User.DoesNotExist:
    	if not verified:
    		key = misc.generate_confirmation_key()
    		emails.send_confirmation_email(email, name, key)
    		user = User.create(name = name, email = email, conf_key = key)
    		session['user_id'] = user.id
    		flash("Ahoy! You're in the system please enter these important details")
    		return redirect(url_for('first_social'))
    	else:
    		user = User.create(name = name , email = email, emailconf = verified)
    		session["user_id"] = user.id
    		flash("Ahoy! You're in the system please enter these important details")
    		return redirect(url_for('first_social'))

@app.route('/first-social/', methods=["GET", "POST"])
@decorators.login_required
def first_social():
	if request.method == "GET":
		return render_template("first_social.html")

	elif request.method == "POST":
		isAteacher = "teacher" in request.form
		standard = request.form["standard"].strip()
		section = request.form['section'].strip()
		school = request.form['school'].strip()
		if not isAteacher:
			isAteacher = False

		if not standard:
			flash("Please select a standard!")
			return render_template('first_social.html')

		if not section or len(section) > 1:
			flash("Please enter a valid section!")
			return render_template('first_social.html')

		if not school:
			flash("Please enter a valid school matey!")
			return render_template('first_social.html')

		g.user.isATeacher = isAteacher
		g.user.standard = standard
		g.user.section = section
		g.user.school = school
		g.user.firstsociallogin = False
		g.user.save()
		flash("Thank you very much for the details!")
		return redirect(url_for("dashboard"))


@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('oauth_token')


#===============GOOGLE LOGIN================
@app.route('/google-data/')
def google_data():
    access_token = session.get('google_access_token')
    if access_token is None:
        return redirect(url_for('login'))
 
    access_token = access_token[0]
    from urllib2 import Request, urlopen, URLError
 
    headers = {'Authorization': 'OAuth '+access_token}
    req = Request('https://www.googleapis.com/oauth2/v1/userinfo',
                  None, headers)
    try:
        res = urlopen(req)
    except URLError, e:
        if e.code == 401:
            # Unauthorized - bad token
            session.pop('google_access_token', None)
            flash("Oops! Authorization Error!")
            return redirect(url_for('login'))
        data = res.read()
 
    data = eval(res.read().replace('true', 'True'))
    name = data['name'].strip()
    email = data['email'].strip()
    try:
    	user = User.get(User.email == email)
    	session['user_id'] = user.id
    	flash("Logged in using google!")
    	return redirect(url_for('login'))

    except User.DoesNotExist:
    	user = User.create(name = name, email = email, emailconf = 1)
    	session['user_id'] = user.id
    	emails.send_welcome_email(user.email, user.name, "Google")
    	return redirect(url_for('dashboard'))




@app.route('/google-login/')
def google_login():
    callback=url_for('authorized', _external=True)
    return google.authorize(callback=callback)


@app.route(REDIRECT_URI)
@google.authorized_handler
def authorized(resp):
    access_token = resp['access_token']
    session['google_access_token'] = access_token, ''
    return redirect(url_for('google_data'))
 
 
@google.tokengetter
def get_access_token():
    return session.get('google_access_token')






@app.before_request
def before_request():
	db.connect()

def allowed_files(name):
	exts = ['.jpg', '.jpeg', '.pdf']
	for i in exts:
		if name.endswith(i):
			return True
	return False

def generate_name(name):
	if name.endswith('.jpeg'):
		ext = name[len(name)-5::]
	else:
		ext = name[len(name)-4::]
	name = name.strip(ext)
	name += "_"+misc.generate_random_string(32)
	name += ext
	return name


if __name__ == "__main__":
	app.run(host="127.0.0.1", port=80)
