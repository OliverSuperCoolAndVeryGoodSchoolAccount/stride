import sqlite3
from datetime import datetime
from sqlite3 import Error

from flask import Flask, render_template, request, session, redirect, flash
from flask_bcrypt import Bcrypt
from flask_recaptcha import ReCaptcha

DB_NAME = "C:\\Users\\16107\\OneDrive - Wellington College\\stride\\stride\\stride.db"

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "a"

app.config.update(dict(
    RECAPTCHA_ENABLED=True,
    RECAPTCHA_SITE_KEY="6LdhesIZAAAAALIKktWfQmkzm75jMVRTkEO0RAuP",
    RECAPTCHA_SECRET_KEY="6LdhesIZAAAAANy7GTtv0LeIKrCJI5fKMmRTNh-m",
    RECAPTCHA_THEME="dark",
))

recaptcha = ReCaptcha()
recaptcha.init_app(app)


def create_connection(db_file):
    """create a connection to the sqlite db"""
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:
        print(e)

    return None


@app.route('/', methods=["GET", "POST"])
def render_homepage():
    if not is_logged_in():
        return redirect('/login')
    if request.method == "POST":
        if recaptcha.verify():
            userid = session['userid']
            post = request.form['message'].strip()
            if not 1 <= len(post) <= 280:
                flash("Error: Invalid input in text box")
                return redirect('/')
            time = datetime.now()
            query = "INSERT INTO posts(id,post,time,customer_id) VALUES (NULL,?,?,?)"
            con = create_connection(DB_NAME)
            cur = con.cursor()
            cur.execute(query, (post, time, userid))
            con.commit()
            con.close()
            return redirect('/')
            pass
        else:
            flash("Captcha failed, please try again.")
            return redirect('/')

    con = create_connection(DB_NAME)

    # SELECT the things you want from your table(s)
    query = """SELECT posts.id,customer.fname,customer.lname,posts.post,strftime('%d/%m/%Y %H:%M:%S', posts.time) AS time 
            FROM posts,customer
            WHERE posts.customer_id = customer.id
            ORDER BY time DESC"""
            #Add limit?

    cur = con.cursor()  # You need this line next
    cur.execute(query)  # this line actually executes the query
    post_list = cur.fetchall()  # puts the results into a list usable in python
    con.close()
    return render_template('home.html', logged_in=is_logged_in(), posts=post_list,)


@app.route('/profile')
def render_profile():
    if is_logged_in():
        return redirect('/profile/' + str(session['userid']))
    else:
        flash("Error: user not logged in")
        return redirect("/")


@app.route('/contact')
def render_contact_page():
    return render_template('contact.html', logged_in=is_logged_in())


@app.route('/login', methods=["GET", "POST"])
def render_login_page():
    if is_logged_in():
        return redirect('/')

    if request.method == "POST":
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()

        query = """SELECT id, fname, password FROM customer WHERE email = ?"""
        con = create_connection(DB_NAME)
        cur = con.cursor()
        cur.execute(query, (email,))
        user_data = cur.fetchall()
        con.close()
        # if given the email is not in the database this will raise an error
        # would be better to find out how to see if the query return an empty resultset
        try:
            userid = user_data[0][0]
            firstname = user_data[0][1]
            db_password = user_data[0][2]
        except IndexError:
            return redirect("/login?error=Email+invalid+or+password+incorrect")

        # check if the password is incorrect for that email address

        if not bcrypt.check_password_hash(db_password, password):
            return redirect(request.referrer + "?error=Email+invalid+or+password+incorrect")

        session['email'] = email
        session['userid'] = userid
        session['firstname'] = firstname
        print(session)
        return redirect('/')

    return render_template('login.html', logged_in=is_logged_in())


@app.route('/signup', methods=['GET', 'POST'])
def render_signup_page():
    if is_logged_in():
        return redirect('/')

    if request.method == 'POST':
        print(request.form)
        fname = request.form.get('fname').strip().title()
        lname = request.form.get('lname').strip().title()
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        password2 = request.form.get('password2')

        if password != password2:
            flash('Passwords dont match')
            return redirect('/signup?error=Passwords+dont+match')

        if len(password) < 8:
            flash('Password must be 8 characters or longer')
            return redirect('/signup?error=Password+must+be+8+characters+or+more')

        hashed_password = bcrypt.generate_password_hash(password)

        con = create_connection(DB_NAME)

        query = "INSERT INTO customer(id, fname, lname, email, password) " \
                "VALUES(NULL,?,?,?,?)"

        cur = con.cursor()  # You need this line next
        try:
            cur.execute(query, (fname, lname, email, hashed_password))  # this line actually executes the query
        except sqlite3.IntegrityError:
            flash('Email is already used')
            return redirect('/signup?error=Email+is+already+used')

        con.commit()
        con.close()
        return redirect('/login')

    return render_template('signup.html', logged_in=is_logged_in())


@app.route('/logout')
def logout():
    print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]
    print(list(session.keys()))
    flash("See you next time!")
    return redirect(request.referrer)

@app.route('/profile/<userid>')
def user(userid):
    con = create_connection(DB_NAME)
    query = "SELECT COUNT(*) FROM customer WHERE id = ?"
    cur = con.cursor()  # You need this line next
    cur.execute(query, (userid,))  # this line actually executes the query
    profilecount = cur.fetchall()[0][0]  # puts the results into a list usable in python
    if profilecount < 1:
        flash("No user with " + str(userid) + " as their id.")
        return redirect("/")

    query = """SELECT posts.id,customer.fname,customer.lname,posts.post,strftime('%d/%m/%Y %H:%M:%S', posts.time) AS time
                FROM posts,customer
                WHERE posts.customer_id = ? AND posts.customer_id = customer.id
                ORDER BY time DESC"""
    cur = con.cursor()  # You need this line next
    cur.execute(query, (userid,))  # this line actually executes the query
    post_list = cur.fetchall()  # puts the results into a list usable in python

    con = create_connection(DB_NAME)
    query = "SELECT fname,lname FROM customer WHERE id = ?"
    cur = con.cursor()  # You need this line next
    cur.execute(query, (userid,))  # this line actually executes the query
    user_info = cur.fetchall()

    con.close()
    return render_template('profile.html', logged_in=is_logged_in(), posts=post_list, userinfo = user_info,)


def is_logged_in():
    if session.get("email") is None:
        print("not logged in")
        return False
    else:
        print("logged in")
        return True


app.run(host='0.0.0.0', debug=True)
