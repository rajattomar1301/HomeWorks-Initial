from flask import session, redirect, url_for, flash, g, abort
from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" in session and session["user_id"]:
            return f(*args, **kwargs)
        else:
            flash("You need to be logged in to access this page.")
            return redirect(url_for('login'))
    return decorated

def confirmed_email_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" in session and session["user_id"]:
            if not g.user.emailconf:
                flash("Please confirm your email in order to access that page.")
                return redirect(url_for('dashboard'))
            else:
                return f(*args, **kwargs)
        else:
            flash("You need to be logged in to access that page.")
            return redirect(url_for('login'))
    return decorated


def teacher_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.user.isATeacher:
            return f(*args, **kwargs)
        else:
            flash("You need to be a teacher to be able to access this page.")
            return redirect(url_for('dashboard'))
    return decorated


def student_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.user.isATeacher:
            return f(*args, **kwargs)
        else:
            flash("You need to be a student to be able to access this page.")
            return redirect(url_for('dashboard'))
    return decorated

def data_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.user.firstsociallogin:
            return f(*args, **kwargs)
        else:
            flash("You need to enter the additional information to access this page :)")
            return redirect(url_for('first_social'))
    return decorated
