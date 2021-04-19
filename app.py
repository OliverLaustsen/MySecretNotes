import json
import sqlite3
import click
import functools
import os
import hashlib
import time
import random
import sys

from flask import Flask, current_app, g, session, redirect, render_template, url_for, request
import hashlib
import binascii
import os
import html


### DATABASE FUNCTIONS ###

def connect_db():
    return sqlite3.connect(app.database)


def init_db():
    """Initializes the database with our great SQL schema"""
    conn = connect_db()
    db = conn.cursor()
    db.executescript("""

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS notes;

CREATE TABLE notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assocUser INTEGER NOT NULL,
    dateWritten DATETIME NOT NULL,
    note TEXT NOT NULL,
    publicID INTEGER NOT NULL
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL
);

INSERT INTO users VALUES(null,"admin", "password");
INSERT INTO users VALUES(null,"bernardo", "omgMPC");
INSERT INTO notes VALUES(null,2,"1993-09-23 10:10:10","hello my friend",1234567890);
INSERT INTO notes VALUES(null,2,"1993-09-23 12:10:10","i want lunch pls",1234567891);

""")


def sanitize(input):
    if(isinstance(input, str)):
        out = html.escape(input)
    else:
        out = []
        for s in input:
            out.append(html.escape(s))
    return out

### HASHING FUNCTION ###
# Credit to https://www.vitoshacademy.com/hashing-passwords-in-python/ for the function


def hash_password(password):
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'),
                                  salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')


def verify_hashed_password(stored_password, provided_password):
    """Verify a stored password against one provided by user"""
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512',
                                  provided_password.encode('utf-8'),
                                  salt.encode('ascii'),
                                  100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_password

### PASSWORD STRENGTH FUNCTION ###


def strength_check_of_password(password):
    specialSymbols = ['$', '!', '@', '#', '%', '/',
                      '(', ')', '[', ']', '{', '}', '£', '<', '>', '=', '.', ':', ',', ';', '-', '_']
    if(len(password) < 6):
        return False
    '''
    if not any(char.isdigit() for char in password):
        return False

    if not any(char.isupper() for char in password):
        return False

    if not any(char.islower() for char in password):
        return False

    if not any(char in specialSymbols for char in password):
        return False 
    '''
    return True


    ### APPLICATION SETUP ###
app = Flask(__name__)
app.database = "db.sqlite3"
app.secret_key = os.urandom(32)

### ADMINISTRATOR'S PANEL ###


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view


@app.route("/")
def index():
    if not session.get('logged_in'):
        return render_template('index.html')
    else:
        return redirect(url_for('notes'))

@app.route("/files/")
def files():
    return render_template('files.html')

@app.route("/notes/", methods=('GET', 'POST'))
@login_required
def notes():
    importerror = ""
    # Posting a new note:
    if request.method == 'POST':
        if request.form['submit_button'] == 'add note':
            note = request.form['noteinput']
            db = connect_db()
            c = db.cursor()
            #statement = """INSERT INTO notes(id,assocUser,dateWritten,note,publicID) VALUES(null,%s,'%s','%s',%s);""" %(session['userid'],time.strftime('%Y-%m-%d %H:%M:%S'),note,random.randrange(1000000000, 9999999999))
            # print(statement)
            c.execute("INSERT INTO notes(id,assocUser,dateWritten,note,publicID) VALUES(null,?,?,?,?)", (
                session['userid'], time.strftime('%Y-%m-%d %H:%M:%S'), note, random.randrange(1000000000, 9999999999)))
            db.commit()
            db.close()
        elif request.form['submit_button'] == 'import note':
            noteid = request.form['noteid']
            db = connect_db()
            c = db.cursor()
            #statement = """SELECT * from NOTES where publicID = %s""" %noteid
            c.execute("SELECT * from NOTES where publicID = ?", (noteid))
            result = c.fetchall()
            print(result)
            if(len(result) > 0):
                row = result[0]
                statement = """INSERT INTO notes(id,assocUser,dateWritten,note,publicID) VALUES(null,%s,'%s','%s',%s);""" % (
                    session['userid'], row[2], row[3], row[4])
                c.execute(statement)
            else:
                importerror = "No such note with that ID!"
            db.commit()
            db.close()

    db = connect_db()
    c = db.cursor()
    statement = "SELECT * FROM notes WHERE assocUser = %s;" % session['userid']
    print(statement)
    c.execute(statement)
    notes = c.fetchall()
    print(notes)

    return render_template('notes.html', notes=notes, importerror=importerror)


@app.route("/login/", methods=('GET', 'POST'))
def login():
    error = ""
    if request.method == 'POST':
        username = sanitize(request.form['username'])
        password = sanitize(request.form['password'])
        db = connect_db()
        c = db.cursor()
        # No need to find password with the new hashing.
        statement = "SELECT * FROM users WHERE username = '%s'" % (username)
        c.execute(statement)
        result = c.fetchall()

        if len(result) > 0:
            if(not verify_hashed_password(result[0][2], password)):
                error = "You entered a wrong password"
                return render_template('login.html', error=error)
            else:
                session.clear()
                session['logged_in'] = True
                session['userid'] = result[0][0]
                session['username'] = result[0][1]
                return redirect(url_for('index'))
    return render_template('login.html', error=error)


@app.route("/register/", methods=('GET', 'POST'))
def register():
    errored = False
    usererror = ""
    passworderror = ""
    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        if(not strength_check_of_password(password)):
            # maybe add more info - consider letting strength function return a tuple of (bool, string) to pass the correct error message.
            usererror = "password is too weak"
            return render_template('register.html', usererror=usererror, passworderror=passworderror)

        password = hash_password(password)
        db = connect_db()
        c = db.cursor()

        pass_statement = """SELECT * FROM users WHERE password = '%s';""" % password  # Maybe not needed? same password for different users is fine?
        user_statement = """SELECT * FROM users WHERE username = '%s';""" % username
        c.execute(pass_statement)
        if(len(c.fetchall()) > 0):
            errored = True
            passworderror = "That password is already in use by someone else!"

        c.execute(user_statement)
        if(len(c.fetchall()) > 0):
            errored = True
            usererror = "That username is already in use by someone else!"

        if(not errored):
            statement = """INSERT INTO users(id,username,password) VALUES(null,'%s','%s');""" % (
                username, password)
            print(statement)
            c.execute(statement)
            db.commit()
            db.close()
            return f"""<html>
                        <head>
                            <meta http-equiv="refresh" content="2;url=/" />
                        </head>
                        <body>
                            <h1>SUCCESS!!! Redirecting in 2 seconds...</h1>
                        </body>
                        </html>
                        """

        db.commit()
        db.close()
    return render_template('register.html', usererror=usererror, passworderror=passworderror)


@app.route("/logout/")
@login_required
def logout():
    """Logout: clears the session"""
    session.clear()
    return redirect(url_for('index'))


if __name__ == "__main__":
    # create database if it doesn't exist yet
    if not os.path.exists(app.database):
        init_db()
    runport = 5000
    if(len(sys.argv) == 2):
        runport = sys.argv[1]
    try:
        # runs on machine ip address to make it visible on netowrk
        app.run(host='0.0.0.0', port=runport)
    except:
        print("Something went wrong. the usage of the server is either")
        print("'python3 app.py' (to start on port 5000)")
        print("or")
        print("'sudo python3 app.py 80' (to run on any other port)")
