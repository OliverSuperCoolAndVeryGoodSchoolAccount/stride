import os
import sqlite3
from datetime import datetime
from sqlite3 import Error

from flask import Flask, render_template, request, session, redirect, flash, jsonify, url_for
from flask_bcrypt import Bcrypt
from flask_recaptcha import ReCaptcha
from werkzeug.utils import secure_filename

from PIL import Image
from math import ceil

DB_NAME = "C:\\Users\\t.harford\\PycharmProjects\\stride\\stride.db"

UPLOAD_FOLDER = 'C:\\Users\\t.harford\\PycharmProjects\\stride\\static\\images\\user_uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'jfif', 'heic'}

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "a"

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/posts', methods=["GET"])
def get_posts():
    lastid = request.args.get('id')
    con = create_connection(DB_NAME)
    now = datetime.now()
    query = """SELECT posts.id,users.fname,users.lname,posts.post,strftime('%d/%m/%Y %H:%M:%S', posts.time) AS time, users.id,posts.imagename 
            FROM posts,users
            WHERE posts.customer_id = users.id AND posts.id > ?
            ORDER BY posts.time DESC"""
    # Add limit?
    cur = con.cursor()  # You need this line next

    cur.execute(query, (lastid,))  # this line actually executes the query
    post_list = cur.fetchall()  # puts the results into a list usable in python
    con.close()
    return jsonify(post_list)


@app.route('/', methods=["GET", "POST"])
def render_homepage():
    if not is_logged_in():
        return redirect('/login')
    if request.method == "POST":
        if not recaptcha.verify():
            flash("Captcha failed, please try again.")
            return redirect('/')

        userid = session['userid']
        post = request.form['message'].strip()

        time = datetime.now()  # for file name and post time
        filename = ""

        # this seems to be always true
        if 'file' in request.files:
            file = request.files['file']

            if file.filename == '':
                # there is no file, check if it is a text stride
                if not 1 <= len(post) <= 280:
                    flash("Your Stride must be no more than 280 characters!")
                    return redirect('/')

            elif allowed_file(file.filename):
                # ensure the image name is unique so we don't overwrite
                filename = secure_filename(str(userid) + "_" + str(time) + "_" + file.filename)
                # save the image to specified directory
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                # use Pillow to resize
                # scale to be no larger than 640px wide and 480px high
                image = Image.open(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                width, height = image.size[0], image.size[1]
                print(width, height)
                MAX_WIDTH, MAX_HEIGHT = 640, 480
                if width > MAX_WIDTH or height > MAX_HEIGHT:
                    x_factor = ceil(width / MAX_WIDTH)
                    y_factor = ceil(height / MAX_HEIGHT)
                    if x_factor > y_factor:
                        x, y = int(ceil(width / x_factor)), int(ceil(height / x_factor))
                    else:
                        x, y = int(ceil(width / y_factor)), int(ceil(height / y_factor))
                    image = image.resize((x, y))
                    image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            else:
                flash('This file type is not allowed')
                return redirect('/')

        query = "INSERT INTO posts(id,post,time,customer_id,imagename) VALUES (NULL,?,?,?,?)"
        con = create_connection(DB_NAME)
        cur = con.cursor()
        cur.execute(query, (post, time, userid, filename))
        con.commit()
        con.close()
        return redirect('/')

    con = create_connection(DB_NAME)
    query = """SELECT posts.id,users.fname,users.lname,posts.post,strftime('%d/%m/%Y %H:%M:%S', posts.time) AS time, users.id,posts.imagename 
                FROM posts,users
                WHERE posts.customer_id = users.id
                ORDER BY posts.time DESC
                LIMIT 20"""

    cur = con.cursor()  # You need this line next
    cur.execute(query)  # this line actually executes the query
    post_list = cur.fetchall()  # puts the results into a list usable in python
    con.close()

    # SELECT the things you want from your table(s)

    return render_template('home.html', logged_in=is_logged_in(), posts=post_list)


@app.route("/sys_info.json")
def system_info():  # you need an endpoint on the server that returns your info...
    return get_system_info()


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

        query = """SELECT id, fname, password FROM users WHERE email = ?"""
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

        query = "INSERT INTO users(id, fname, lname, email, password) " \
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
def profile(userid):
    # if userid == "19":
    #      return redirect("https://www.latlmes.com/breaking/breaking-1")
    con = create_connection(DB_NAME)
    query = "SELECT COUNT(*) FROM users WHERE id = ?"
    cur = con.cursor()  # You need this line next
    cur.execute(query, (userid,))  # this line actually executes the query
    profilecount = cur.fetchall()[0][0]  # puts the results into a list usable in python
    if profilecount < 1:
        flash("No user with " + str(userid) + " as their id.")
        return redirect("/")

    query = """SELECT posts.id,users.fname,users.lname,posts.post,strftime('%d/%m/%Y %H:%M:%S', posts.time) AS time
                FROM posts,users
                WHERE posts.customer_id = ? AND posts.customer_id = users.id
                ORDER BY posts.time DESC"""
    cur = con.cursor()  # You need this line next
    cur.execute(query, (userid,))  # this line actually executes the query
    post_list = cur.fetchall()  # puts the results into a list usable in python

    con = create_connection(DB_NAME)
    query = "SELECT fname,lname,biography,relationship,id FROM users WHERE id = ?"
    cur = con.cursor()  # You need this line next
    cur.execute(query, (userid,))  # this line actually executes the query
    user_info = cur.fetchall()

    con.close()
    correct_user = False
    if str(session['userid']) == str(userid):
        correct_user = True

    return render_template('profile.html', logged_in=is_logged_in(), correctuser=correct_user, posts=post_list,
                           userinfo=user_info, )


@app.route('/profile/<userid>/edit', methods=["GET", "POST"])
def editprofile(userid):
    if str(session['userid']) == str(userid):
        if str(userid) == str(15):
            return redirect("https://www.latlmes.com/breaking/breaking-1")
        con = create_connection(DB_NAME)
        if request.method == "POST":
            biography = request.form['bio'].strip()
            relationship = request.form['status'].strip()
            query = "UPDATE users SET biography=?,relationship=? WHERE id=?"
            cur = con.cursor()
            cur.execute(query, (biography, relationship, userid))
            con.commit()

        query = """SELECT posts.id,users.fname,users.lname,posts.post,strftime('%d/%m/%Y %H:%M:%S', posts.time) AS time
                                FROM posts,users
                                WHERE posts.customer_id = ? AND posts.customer_id = users.id
                                ORDER BY posts.time DESC"""
        cur = con.cursor()
        cur.execute(query, (userid,))  # this line actually executes the query
        post_list = cur.fetchall()  # puts the results into a list usable in python

        con = create_connection(DB_NAME)
        query = "SELECT fname,lname,biography,relationship,id FROM users WHERE id = ?"
        cur.execute(query, (userid,))  # this line actually executes the query
        user_info = cur.fetchall()
        con.close()

        return render_template('editprofile.html', logged_in=is_logged_in(), posts=post_list, userinfo=user_info, )
    else:
        flash("You cannot edit a profile that is not yours.")
        return redirect("/profile/" + str(userid))


def is_logged_in():
    if session.get("email") is None:
        print("not logged in")
        return False
    else:
        print("logged in")
        return True


if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
