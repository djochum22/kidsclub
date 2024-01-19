import os


from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required, instructor_required

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"


Session(app)

db = SQL("sqlite:///project.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":
        if not request.form.get("email"):
            flash("must provide email")
            print(403)
            return render_template("login.html")

        elif not request.form.get("password"):
            flash("must provide password")
            print(403)
            return render_template("login.html")

        email = db.execute(
            "SELECT * FROM users WHERE email = ?", request.form.get("email")
        )

        if len(email) != 1 or not check_password_hash(
            email[0]["hash"], request.form.get("password")
        ):
            flash("email and/or password incorrect")
            print(403)
            return render_template("login.html")

        session["user_id"] = email[0]["id"]
        session["user_email"] = email[0]["email"]
        session["user_role"] = email[0]["role"]

        return redirect("/i_homepage")

    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if (
            not first_name
            or not last_name
            or not email
            or not password
            or not confirmation
        ):
            flash("Please fill in all fields")
            print(400)
            return render_template("register.html")

        if password != confirmation:
            flash("password and confirmation do not match")
            print(400)
            return render_template("register.html")

        existing_user = db.execute("SELECT * FROM users WHERE email = ?", email)

        if existing_user:
            flash(
                "This email has already been used for an account, please provide a different email"
            )
            return render_template("register.html")

        hashed_password = generate_password_hash(password)

        db.execute(
            "INSERT INTO users (first_name, last_name, email, hash) VALUES (?, ?, ?, ?)",
            first_name,
            last_name,
            email,
            hashed_password,
        )

        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()

    return redirect("/")


@app.route("/", methods=["GET", "POST"])
@login_required
def p_homepage():
    if request.method == "POST":
        date = request.form.get("date")
        student = request.form.get("students")
        dropoff = request.form.get("dropoff")
        eta = request.form.get("time")

        
        if not date or not student or not dropoff or not eta:
            flash("Fill in all required fields")
            print(400)
            return render_template("p_homepage.html")

        user_id = session.get("user_id")

        student_id = db.execute("SELECT id FROM students WHERE name = ?", student)

        existing_row = db.execute(
            "SELECT * FROM schedule WHERE user_id = ? AND student_id = ?",
            user_id,
            student_id[0]["id"],
        )

        if not existing_row:
            db.execute(
                "INSERT INTO schedule (user_id, student_id, date, dropoff, eta) VALUES (?, ?, ?, ?, ?)",
                user_id,
                student_id[0]["id"],
                date,
                dropoff,
                eta,
            )
        else:
            db.execute(
                "UPDATE schedule SET date = ?, dropoff = ?, eta = ? WHERE user_id = ? AND student_id = ?",
                date,
                dropoff,
                eta,
                user_id,
                student_id[0]["id"],
            )

        schedule_student_information = db.execute(
            "SELECT s.name, sch.date, sch.dropoff, sch.eta FROM students s JOIN schedule sch ON s.id = sch.student_id WHERE sch.date = ? AND sch.user_id = ?",
            date,
            user_id,
        )
        
        students_name = db.execute("SELECT * FROM students WHERE user_id = ? ORDER BY name", user_id)

        return render_template(
            "p_homepage.html",
            students=students_name,
            schedule_student_information=schedule_student_information,
        )

    else:
        user_id = session.get("user_id")
        students_name = db.execute("SELECT * FROM students WHERE user_id = ? ORDER BY name", user_id)
        return render_template(
            "p_homepage.html",
            students=students_name,
            schedule_student_information=None,
            selected_date=None,
        )
        
@app.route("/scheduleinformation", methods=["GET", "POST"])
@login_required
def scheduleinformation():
    if request.method == "POST": 
        date = request.form.get("date")
        if not date:
                flash("Fill in all required fields")
                print(400)
                return render_template("p_homepage.html")
        
        user_id = session.get("user_id")
        
        students_name = db.execute("SELECT * FROM students WHERE user_id = ? ORDER BY name", user_id)

        existing_row = db.execute(
            "SELECT * FROM schedule WHERE user_id = ?",
            user_id,
        )
        
        if not existing_row:
            return render_template("p.homepage.html")
        else:
            schedule_student_information = db.execute(
                "SELECT s.name, sch.date, sch.dropoff, sch.eta FROM students s JOIN schedule sch ON s.id = sch.student_id WHERE sch.date = ? AND sch.user_id = ?",
                date,
                user_id,
            )
            return render_template("p_homepage.html", students=students_name, schedule_student_information=schedule_student_information)
    
    else:
        user_id = session.get("user_id")
        students_name = db.execute("SELECT * FROM students WHERE user_id = ? ORDER BY name", user_id)
        return render_template(
            "p_homepage.html",
            students=students_name,
            schedule_student_information=None,
            selected_date=None,
        )    

@app.route("/remove", methods=["POST"])
@login_required
def remove_student():
    print("Removing student route accessed!")
    if request.method == "POST":
        try:
            user_id = session.get("user_id")
            student_id_to_remove = request.form.get("remove_student_id")
            date = request.form.get("date")

            print(user_id)
            print(student_id_to_remove)
            print(date)
            
            if student_id_to_remove and date:
                db.execute(
                    "DELETE FROM schedule WHERE user_id = ? AND student_id = ? AND date = ?",
                    user_id,
                    student_id_to_remove,
                    date,
                )

            print("Student removed successfully!")
            return "Success"
        except Exception as e:
            print("Error removing student:", str(e))
            return "Error"
    else:
        return render_template("error.html", message="Invalid request", code=400)

@app.route("/i_homepage", methods=["GET", "POST"])
@login_required
@instructor_required
def i_homepage():
    user_email = session.get("user_email")
    role = db.execute(
        "UPDATE users SET role = 'instructor' WHERE email = ?", user_email
    )
    if request.method == "POST":
        date = request.form.get("date")

        schedule_student_information = db.execute(
            "SELECT s.name, sch.date, sch.dropoff, sch.eta FROM students s JOIN schedule sch ON s.id = sch.student_id WHERE sch.date = ?",
            date,
        )

        role = db.execute(
            "UPDATE users SET role = 'instructor' WHERE email = ?", user_email
        )

        return render_template(
            "i_homepage.html",
            schedule_student_information=schedule_student_information,
            role=role,
        )
    else:
        return render_template("i_homepage.html")


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        email = request.form.get("email")
        oldpassword = request.form.get("oldpassword")
        newpassword = request.form.get("newpassword")
        confirmation = request.form.get("confirmation")

        rows = db.execute("SELECT * FROM users WHERE email = ?", email)

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], oldpassword):
            flash("Invalid email and/or old password")
            print(403)
            return render_template("change_password.html")

        if newpassword != confirmation:
            flash("New password and confirmation do not match")
            print(403)
            return render_template("change_password.html")

        hashed_password = generate_password_hash(newpassword)
        db.execute(
            "UPDATE users SET hash = ? WHERE id = ?",
            hashed_password,
            session["user_id"],
        )

        return redirect("/settings")
    else:
        return render_template("change_password.html")


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    user_id = session.get("user_id")

    if user_id is None:
        flash("User not logged in")
        return redirect("/login")

    email_data = db.execute("SELECT email FROM users WHERE id = ?", user_id)

    if email_data:
        email = email_data[0]["email"]
        return render_template("settings.html", email=email)
    else:
        flash("User not found")
        return redirect("/login")
