from flask import redirect, session
from functools import wraps


def login_required(f):
    """
    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


def instructor_required(f):
    """
    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        allowed_emails = {"instructor1@fisw.edu", "instructor2@fisw.edu", "instructor3@fisw.edu", "instructor4@fisw.edu"}

        user_email = session.get("user_email")

        if user_email not in allowed_emails:
            return redirect("/")

        return f(*args, **kwargs)

    return decorated_function
