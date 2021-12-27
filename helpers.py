import os
import requests
import re

from flask import redirect, render_template, request, session
from functools import wraps

def apology(msg):
    return render_template('apology.html', error=msg)

def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/register")
        return f(*args, **kwargs)
    return decorated_function

def validate(password):
    # special chars
    pattern = '[!@#$%^&*()-+?_=,<>/;:"~`]'

    # checks if password length is greater than 8 and contains at least 1 capital letter, 1 digit, and 1 special char
    if len(password) < 8:
        return False
    if re.search('[0-9]', password) is None:
        return False
    if re.search('[A-Z]', password) is None:
        return False
    if re.search(pattern, password) is None:
        return False

    return True

def checkClubName(name):
    # special chars
    pattern = '[!@#$%^&*()-+?_=,<>/;:"~`]'

    if re.search(pattern, name) is None:
        return False

    return True

def checkStudentNames(name):
    # special chars
    pattern = '[!@#$%^&*()-+?_=,<>/;:~`]'

    if re.search(pattern, name) is None and re.search('[0-9]', name) is None:
        return False

    return True


