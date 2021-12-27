import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for, send_from_directory
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import imghdr

from helpers import apology, login_required, validate, checkClubName, checkStudentNames

# Configure application, recall __name__ = file name
app = Flask(__name__)

# app.config is a subclass of a dict and can be treated like a dict

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# max file size for images is 1MB
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024

# where to store the uploaded files
app.config['UPLOAD_FOLDER'] = 'uploads'

# what file extensions are accepted
app.config['UPLOAD_EXTENSIONS'] = ['.png', '.jpg', '.gif']

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///clubs.db")

# holds the possible day options
DAYS = ['Sundays', 'Mondays', 'Tuesdays', 'Wednesdays', 'Thursdays', 'Fridays', 'Saturdays','TBD']

# Ensure responses aren't cached (if a user logs out, their data won't be saved for the next user on the same device)
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@app.route('/landing')
def landing():
    return render_template('landing.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register user"""

    # creates the users database if it is not created yet
    users = db.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='users' ''')
    if users[0]['count(name)'] == 0:
        db.execute('CREATE TABLE users (userId INTEGER PRIMARY KEY, clubUsername TEXT, firstName TEXT, lastName TEXT, studentNumber NUMERIC, type TEXT NOT NULL, password TEXT NOT NULL, clubsSignedUp TEXT)')

    if request.method == 'POST':

        # checks if club account is clicked
        if request.form.get('club') == 'Club':
            return render_template('register.html', club=True)

        # checks if student account is clicked
        if request.form.get('student') == 'Student':
            return render_template('register.html', student=True)

        # ensures password is provided
        if not request.form.get("password"):
            return apology("Must provide password!")

        # ensures password is retyped
        if not request.form.get("confirmation"):
            return apology("Must retype password!")

        # checks if the passwords match
        if request.form.get('password') != request.form.get('confirmation'):
            return apology('Passwords do not match!')

        # checks if the password follows a certain structure
        if not validate(request.form.get('password')):
            return apology('Your password must be at least 8 characters long, contain capital letters, special characters, numbers, and must not contain spaces or emoji.')

        # checks a hidden field on the form to see if the form submitted is a club form
        if request.form.get('chooseAccount') == 'club':

            # ensures club name is entered
            if not request.form.get("clubName"):
                return apology("Must provide club name!")

            # checks if clubName contains special chars
            if checkClubName(request.form.get("clubName")):
                return apology('Club name cannot contain any special characters!')

            clubName = request.form.get('clubName')

            # removes spaces in the club name
            clubName = ' '.join(clubName.split(','))

            # queries for all the club usernames in the db
            clubUsernames = db.execute('SELECT users.clubUsername FROM users WHERE users.type = ?', 'club')

            # for each user, check if the desired username has been taken
            for i in range(len(clubUsernames)):
                if clubUsernames[i]['clubUsername'].upper().replace(" ", "") == clubName.upper().replace(" ", ""):
                    return apology('Club name already taken!')

            flash('Thank you for registering!')

            # insert new club user into the database
            db.execute('INSERT INTO users (clubUsername, password, type) VALUES(?, ?, ?)', clubName, generate_password_hash(request.form.get('password')), 'club')

        # checks a hidden field on the form to see if the form submitted is a student for
        if request.form.get('chooseAccount') == 'student':

            # ensures first name is entered
            if not request.form.get("firstName"):
                return apology("Must provide first name!")

            # ensures first name does not have special characters or numbers
            if checkStudentNames(request.form.get('firstName')):
                return apology('First name cannot include special characters or numbers!')

            # ensures last name is entered
            if not request.form.get("lastName"):
                return apology("Must provide last name!")

            # ensures first name does not have special characters or numbers
            if checkStudentNames(request.form.get('lastName')):
                return apology('Last name cannot include special characters or numbers!')

            # ensures student number is entered
            if not request.form.get("studentNumber"):
                return apology("Must provide student number!")

            # selects all student numbers in the db
            studentNumbers = db.execute('SELECT users.studentNumber FROM users WHERE users.type = ?', 'student')

            # ensures student number is actually a number
            if not request.form.get('studentNumber').isnumeric():
                return apology('Student Number must only consist of digits!')

            # checks if the user's student number is already in the db
            for i in range(len(studentNumbers)):
                if str(studentNumbers[i]['studentNumber']).replace(" ", "").split() == str(request.form.get('studentNumber')).replace(" ", "").split():
                    return apology('Student number already registered!')

            flash('Thank you for registering!')

            # insert user's information in the db
            db.execute('INSERT INTO users (firstName, lastName, studentNumber, password, type) VALUES(?, ?, ?, ?, ?)', request.form.get("firstName"), request.form.get("lastName"), request.form.get("studentNumber"), generate_password_hash(request.form.get('password')), 'student')

        return render_template('login.html')
    else:
        return render_template('register.html')

# code taken from CS50's finance lab but altered
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # checks if club button is clicked
        if request.form.get('club') == 'Club':
            return render_template('login.html', club=True)

        # checks if student button is clicked
        if request.form.get('student') == 'Student':
            return render_template('login.html', student=True)

        # Ensure password was submitted
        if not request.form.get('password'):
            return apology('Must provide password!')

        # if the user is a club
        if request.form.get('accountType') == 'club':

            # Ensure username was submitted
            if not request.form.get("clubName"):
                return apology("Must provide club name!")

            # Query database for username
            rows = db.execute("SELECT * FROM users WHERE users.clubUsername = ?", request.form.get("clubName"))

            # Ensure username exists and password is correct
            if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
                return apology("Invalid username and/or password!")

            # Remember which user has logged in
            session["user_id"] = rows[0]["userId"]

        else:
            # Ensure username was submitted
            if not request.form.get('studentNumber'):
                return apology('Must provide student number!')

            # Query database for student number
            rows = db.execute("SELECT * FROM users WHERE users.studentNumber = ?", request.form.get("studentNumber"))

            # Ensure student number exists and password is correct
            if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
                return apology("Invalid username and/or password!")

            # Remember which user has logged in
            session["user_id"] = rows[0]["userId"]

        flash('Logged in!')

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("login.html")

@app.route('/changePassword', methods=['GET', 'POST'])
@login_required
def changePassword():

    if request.method == 'POST':

        # obtain user id and form data
        userId = session.get('user_id')
        oldPassword = request.form.get('oldPassword')
        newPassword = request.form.get('newPassword')
        confirm = request.form.get('confirmation')
        oldPassQuery = db.execute('SELECT users.password FROM users WHERE users.userId = ?', userId)

        # ensures old password is entered
        if not oldPassword:
            return apology('Missing old password!')

        # ensures new password is entered
        if not newPassword:
            return apology('Missing new password!')

        # ensures confirmation password is entered
        if not confirm:
            return apology('Retype new password!')

        # checks if old password is entered correctly
        if not check_password_hash(oldPassQuery[0]['password'], oldPassword):
            return apology('Incorrect Password')

        # checks if new password is typed correctly
        if newPassword != confirm:
            return apology('Passwords do not match!')

        # checks if password is of a set structure
        if not validate(newPassword):
            return apology('Your password must be at least 8 characters long, contain capital letters, special characters, numbers, and must not contain spaces or emoji.')

        # update the user's password
        updatePassQuery = 'UPDATE users SET password = ? WHERE users.userId = ?'
        db.execute(updatePassQuery, (generate_password_hash(newPassword)), (userId,))

        flash('Password changed!')

        return redirect('/')
    else:
        return render_template('changePassword.html')


@app.route('/deleteAccount', methods=['GET', 'POST'])
@login_required
def deleteAccount():
    accountType = db.execute('SELECT users.type FROM users WHERE users.userId = ?', session.get('user_id'))

    if request.method == 'POST':

        # obtain user id and form data
        userId = session.get('user_id')
        currentPassword = request.form.get('password')
        confirm = request.form.get('confirmation')

        # queries for user's current password stored in db
        Pass = db.execute('SELECT users.password FROM users WHERE users.userId = ?', userId)

        # ensures password is typed
        if not currentPassword:
            return apology('Missing old password!')

        # ensures password is retyped
        if not confirm:
            return apology('Please retype old password!')

        # checks if password is entered correctly
        if not check_password_hash(Pass[0]['password'], currentPassword):
            return apology('Incorrect Password')

        # checks if password is confirmed
        if currentPassword != confirm:
            return apology('Passwords do not match!')

        # if user is a club
        if accountType[0]['type'] == 'club':
            clubUsername = db.execute('SELECT users.clubUsername FROM users WHERE users.userId = ?', session.get('user_id'))
            clubName = db.execute('SELECT clubs.name FROM clubs WHERE clubs.owner = ?', session.get('user_id'))

            # ensures club name is entered
            if not request.form.get("clubName"):
                return apology("Must provide club username!")

            # ensures club name is correct
            if request.form.get('clubName') != clubUsername[0]['clubUsername']:
                return apology('Incorrect club username entered!')

            # if the club has uploaded a photo, delete it
            if checkPhotos(session.get('user_id')):
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], checkPhotos(session.get('user_id'))))

            # queries for all the student accounts in the db
            studentAccs = db.execute('SELECT users.clubsSignedUp, users.userId FROM users WHERE users.type = ?', 'student')

            # check if the club account has registered a club
            if clubName != []:
                # loop through all of the student accounts
                for i in range(len(studentAccs)):
                    # split the i'th student's clubs
                    userClubs = studentAccs[i]['clubsSignedUp']
                    if userClubs != None and userClubs != '':
                        userClubs = userClubs[:-1]
                        userClubs = userClubs.split(',')
                        newUserClubsStr = ''

                        # loop through the i'th user's clubs
                        for j in range(len(userClubs)):
                            # if the club's name is not the same as the club that is being deleted, add it to the str
                            if userClubs[j] != clubName[0]['name']:
                                newUserClubsStr += userClubs[j] + ','
                    else:
                        newUserClubsStr = ''

                # update the i'th user's clubs
                db.execute('UPDATE users SET clubsSignedUp = ? WHERE users.userId = ?', newUserClubsStr, studentAccs[i]['userId'])

            # deletes club
            db.execute('DELETE FROM clubs WHERE clubs.owner = ?', session.get('user_id'))

            # deletes the club account
            db.execute('DELETE FROM users WHERE users.userId = ?', session.get('user_id'))


        # it is a student account
        else:

            # obtains the user's student number
            studentNumber = db.execute('SELECT users.studentNumber FROM users WHERE users.userId = ?', session.get('user_id'))

            # ensures student number is entered
            if not request.form.get('studentNumber'):
                return apology('Must provide student number!')

            # ensures student number is actually a number
            if not request.form.get('studentNumber').isnumeric():
                return apology('Student Number must only consist of digits!')

            # ensures student number is correct
            if int(request.form.get('studentNumber')) != studentNumber[0]['studentNumber']:
                return apology('Incorrect student number entered!')

            # queries for all the club accounts in the db
            clubs = db.execute('SELECT clubs.members, clubs.club_id FROM clubs')

            # loop through all of the club accounts
            for i in range(len(clubs)):
                # split the i'th clubs's members
                members = clubs[i]['members']
                if members != None and members != '':
                    members = members[:-1]
                    members = members.split(',')
                    newMembersStr = ''

                    # loop through the i'th club's members
                    for j in range(len(members)):
                        # if the j'th member's name is not the same as the student that is being deleted, add it to the str
                        if int(members[j]) != studentNumber[0]['studentNumber']:
                            newMembersStr += members[j] + ','
                else:
                    newMembersStr = ''

                # update the i'th user's clubs
                db.execute('UPDATE clubs SET members = ? WHERE clubs.club_id = ?', newMembersStr, clubs[i]['club_id'])

            # deletes the student account
            db.execute('DELETE FROM users WHERE users.userId = ?', session.get('user_id'))

        flash('Account Deleted!')

        # Forget any user_id
        session.clear()

        return redirect('/register')
    else:
        # if student account, show a student delete account page
        if accountType[0]['type'] == 'student':
            return render_template('deleteAccount.html', student=True)
        # otherwise show a club delete account page
        else:
            return render_template('deleteAccount.html', club=True)

@app.route("/logout")
def logout():
    """Log user out"""

    flash('Logged out!')
    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():

    # checks that clubs table exists
    number = db.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='clubs' ''')

    # if the clubs table doesn't exist, create it
    if number[0]['count(name)'] == 0:
        db.execute('CREATE TABLE clubs (club_id INTEGER PRIMARY KEY, owner INTEGER NOT NULL, name TEXT NOT NULL, president TEXT NOT NULL, description TEXT NOT NULL, days TEXT NOT NULL, members TEXT)')

    userId = session.get('user_id')

    # check the type of account (student or club)
    accountType = db.execute('SELECT users.type FROM users WHERE users.userId = ?', userId)

    # if user is a club account
    if accountType[0]['type'] == 'club':
        # check if the owner already has a club associated with their account
        clubs = db.execute('SELECT clubs.name, clubs.president, clubs.description, clubs.days, clubs.members FROM clubs WHERE clubs.owner = ?', userId)

    if request.method == 'POST':

        # if user is requesting to remove a photo
        if request.form.get('removeClub') == 'removeClub':
            # remove the image from the uploads folder
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], checkPhotos(session.get('user_id'))))
            # if user has not registered a club
            if clubs == []:
                return render_template('index.html', days=DAYS)

            else:
                # creates a dict w/ club details
                club = {}
                club['name'] = clubs[0]['name']
                club['prez'] = clubs[0]['president']
                club['desc'] = clubs[0]['description']
                club['days'] = clubs[0]['days']

                members = clubs[0]['members']

                # lists the members in the club
                if members != None and members != '':
                    members = members[:-1]
                    members = members.split(',')
                    membersStr = ''

                    for i in range(len(members)):
                        if i == len(members) - 1:
                            membersStr += members[i]
                        else:
                            membersStr += members[i] + ', '

                # decides which member data to actually render
                if members == '':
                    membersStr = 'None'
                    club['members'] = membersStr
                elif members != None:
                    club['members'] = membersStr
                else:
                    club['members'] = members

                photo = None

                return render_template('home.html', club=club, days=DAYS, photo=photo)

        # variables to hold form data
        clubName = request.form.get('clubName')
        clubName = ' '.join(clubName.split())

        prezName = request.form.get('presidentName')
        prezName = ' '.join(prezName.split())

        clubDesc = request.form.get('clubDesc')

        selectedDays = []
        clubNames = db.execute('SELECT clubs.name FROM clubs')

        # loops through the potential club days
        for i in range(len(DAYS)):
            # if a day is checked off
            if not request.form.get(DAYS[i]) == None:
                # check if the optional meeting time was entered
                if not request.form.get(DAYS[i]+'Time') == '':
                    selectedDays.append(DAYS[i] + ' @ ' + request.form.get(DAYS[i]+'Time'))
                else:
                    selectedDays.append(DAYS[i])

        # ensures one day option is selected
        if len(selectedDays) == 0:
            return apology('Please select at least one day!')

        # holds string of the club operation days
        dayStr = ''
        for i in range(len(selectedDays)):
            dayStr += (selectedDays[i])
            if i != len(selectedDays) - 1:
                dayStr += ', '

        # if user has not created a club yet
        if clubs == []:
            # loop through all the club names in the db
            for i in range(len(clubNames)):
                # checks if club name is already registered
                if clubNames[i]['name'].upper().replace(" ", "") == clubName.upper().replace(" ", ""):
                    return apology('Club Name already registered!')

            # insert the new club into the db
            db.execute('INSERT INTO clubs (name, owner, president, description, days) VALUES(?,?,?,?,?)', clubName, userId, prezName, clubDesc, dayStr)
            flash('Thank you for registering your club!')

        # user has already created a club and is editing it
        else:
            # update the club data
            updateClubQuery = 'UPDATE clubs SET name = ?, president = ?, description = ?, days = ? WHERE clubs.owner = ?'
            updateClub = db.execute(updateClubQuery, (clubName,), (prezName,), (clubDesc,), (dayStr,), userId)
            flash('Club info updated!')

        # checks if user already has photo uploaded
        if checkPhotos(session.get('user_id')):
            return apology('Club photo file already uploaded')
        else:
            # selects the uploaded file
            file = request.files['img']

            # makes sure the filename is safe
            filename = secure_filename(file.filename)

            # if filename exists
            if filename != '':
                # take file extension
                file_ext = os.path.splitext(filename)[1]
                # check if the file extension is valid
                if file_ext not in app.config['UPLOAD_EXTENSIONS'] or file_ext != validate_image(file.stream):
                    return apology('File type not accepted!')
                # save the file to the photos directory
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], str(session.get('user_id')) + '.' + filename[-3:]))

        return redirect(url_for('index'))

    else:
        # if user is a club account
        if accountType[0]['type'] == 'club':
            # if user has not registered a club
            if clubs == []:
                return render_template('index.html', days=DAYS)

            else:
                # creates a dict w/ club details
                club = {}
                club['name'] = clubs[0]['name']
                club['prez'] = clubs[0]['president']
                club['desc'] = clubs[0]['description']
                club['days'] = clubs[0]['days']

                members = clubs[0]['members']

                # lists the members in the club
                if members != None and members != '':
                    members = members[:-1]
                    members = members.split(',')
                    membersStr = ''

                    for i in range(len(members)):
                        if i == len(members) - 1:
                            membersStr += members[i]
                        else:
                            membersStr += members[i] + ', '

                # decides which member data to actually render
                if members == '':
                    membersStr = 'None'
                    club['members'] = membersStr
                elif members != None:
                    club['members'] = membersStr
                else:
                    club['members'] = members

                photo = None

                # check if user has uploaded a photo
                if checkPhotos(session.get('user_id')):
                    photo = checkPhotos(session.get('user_id'))

                return render_template('home.html', club=club, days=DAYS, photo=photo)
        # user is a student account
        else:
            usersClubs = db.execute('SELECT users.clubsSignedUp FROM users WHERE users.userId = ?', session.get('user_id'))

            # stores a list of dicts of the clubs
            clubsList = []

            if usersClubs[0]['clubsSignedUp'] != None and usersClubs[0]['clubsSignedUp'] != '':

                clubs = usersClubs[0]['clubsSignedUp'][:-1]
                clubs = clubs.split(',')

                print(clubs)

                # loop through all the clubs and find the information of each club
                for i in range(len(clubs)):
                    # holds data for one club that user has signed up for
                    clubDict = {}
                    club = db.execute('SELECT clubs.name, clubs.days FROM clubs WHERE clubs.club_id = ?', int(clubs[i]))
                    clubDict['name'] = club[0]['name']
                    clubDict['days'] = club[0]['days']
                    clubsList.append(clubDict)

            # find the user's first name
            findName = db.execute('SELECT users.firstName FROM users WHERE users.userId=?', userId)

            return render_template('index.html', name=findName[0]['firstName'], clubs=clubsList)

@app.route('/clubs')
@login_required
def listClubs():
    # select all the club names and presidents in the db
    clubs = db.execute('SELECT clubs.name, clubs.president FROM clubs')

    return render_template('clubs.html', clubs=clubs)

@app.route('/clubs/<club>')
@login_required
def showClub(club):
    # find the account type of the user
    accountType = db.execute('SELECT users.type FROM users WHERE users.userId = ?', session.get('user_id'))

    # looks in 'uploads' folder to see if there is a club photo uploaded
    files = os.listdir(app.config['UPLOAD_FOLDER'])

    # initialize variable to hold the photo
    photo = None

    # query the db for item and assign it item
    findClub = db.execute('SELECT * FROM clubs WHERE clubs.name = ?', club)
    clubId = str(findClub[0]['club_id'])

    # use club id
    extensions = ['.png', '.jpg', '.gif']

    for file in files:
        # if the file name == club id
        for i in range(len(extensions)):
            # only prints the current club's (logged in) photo
            if file == str(findClub[0]['owner']) + extensions[i]:
                photo = file

    # store club info in a dict
    details = {}
    details['name'] = findClub[0]['name']
    details['prez'] = findClub[0]['president']
    details['desc'] = findClub[0]['description']
    details['days'] = findClub[0]['days']

    # pass the item to
    if accountType[0]['type'] == 'club':
        return render_template('club.html', details=details, file=photo)
    else:
        # var to check if the user is already registered
        registered = False

        # check if the user has already registered for the club
        findUserClubs = db.execute('SELECT users.clubsSignedUp FROM users WHERE users.userId = ?', session.get('user_id'))
        userClubs = findUserClubs[0]['clubsSignedUp']

        if userClubs != None and userClubs != '':
            userClubs = userClubs[:-1]
            userClubs = userClubs.split(',')

            if clubId in userClubs:
                registered = True

        return render_template('club.html', details=details, file=photo, student=True, clubName=club, registered=registered)

@app.route('/signUp/<clubName>', methods=['POST'])
@login_required
def signUp(clubName):
    # find club details in the db based on the club name
    findClub = db.execute('SELECT clubs.members, clubs.club_id FROM clubs WHERE clubs.name = ?', clubName)
    # check if user is already registered
    findUserClubs = db.execute('SELECT users.clubsSignedUp FROM users WHERE users.userId = ?', session.get('user_id'))
    userClubs = findUserClubs[0]['clubsSignedUp']
    clubId = str(findClub[0]['club_id'])

    # if this is the user's first signed up club
    if userClubs == None:
        userClubs = clubId + ','
    else:
        userClubs = userClubs + clubId + ','

    updateUserClubs = db.execute('UPDATE users SET clubsSignedUp = ? WHERE users.userId = ?', userClubs, session.get('user_id'))

    members = findClub[0]['members']

    studentNumber = db.execute('SELECT users.studentNumber FROM users WHERE users.userId = ?', session.get('user_id'))

    # if user is the first user to sign up
    if members == None:
        members = str(studentNumber[0]['studentNumber']) + ','
    else:
        members += str(studentNumber[0]['studentNumber']) + ','

    updateClubMembers = db.execute('UPDATE clubs SET members = ? WHERE clubs.name = ?', members, clubName)

    flash('Successfully signed up for ' + clubName)

    return redirect(url_for('index'))

@app.route('/leave/<clubName>', methods=['POST'])
@login_required
def leaveClub(clubName):
    # remove from club member list
    studentNumber = db.execute('SELECT users.studentNumber FROM users WHERE users.userId = ?', session.get('user_id'))
    studentNumber = str(studentNumber[0]['studentNumber'])

    members = db.execute('SELECT clubs.members FROM clubs WHERE clubs.name = ?', clubName)
    members = members[0]['members']
    members = members[:-1]
    members = members.split(',')
    newMembersStr = ''

    for i in range(len(members)):
        if members[i] != studentNumber:
            newMembersStr += members[i] + ','

    db.execute('UPDATE clubs SET members = ? WHERE clubs.name = ?', newMembersStr, clubName)

    # remove club from user's clubs

    findUserClubs = db.execute('SELECT users.clubsSignedUp FROM users WHERE users.userId = ?', session.get('user_id'))
    findUserClubs = findUserClubs[0]['clubsSignedUp']
    findUserClubs = findUserClubs[:-1]
    findUserClubs = findUserClubs.split(',')
    newUserClubsStr = ''

    for i in range(len(findUserClubs)):
        if findUserClubs[i] != clubName:
            newUserClubsStr += findUserClubs[i] + ','

    db.execute('UPDATE users SET clubsSignedUp = ? WHERE users.userId = ?', newUserClubsStr, session.get('user_id'))

    flash('Successfully left the club!')

    return redirect(url_for('index'))

@app.route('/faq')
def faq():
    return render_template('faq.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/removeClub')
@login_required
def removeClub():
    clubId = db.execute('SELECT clubs.club_id FROM clubs WHERE clubs.owner = ?', session.get('user_id'))

    # remove this club name from all the users that have it
    studentAccs = db.execute('SELECT users.clubsSignedUp, users.userId FROM users WHERE users.type = ?', 'student')

    # if the user has uploaded an image
    if checkPhotos(session.get('user_id')):
        # remove the image from the uploads folder
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], checkPhotos(session.get('user_id'))))

    # loop through all of the student accounts
    for i in range(len(studentAccs)):
        # check their clubs signed up for column for the deleted club
        userClubs = studentAccs[i]['clubsSignedUp']
        if userClubs != None and userClubs != '':
            userClubs = userClubs[:-1]
            userClubs = userClubs.split(',')
            newUserClubsStr = ''

            # loop through the i'th user's clubs
            for j in range(len(userClubs)):
                # if the club's name is not the same as the club that is being deleted, add it to the str
                if int(userClubs[j]) != clubId[0]['club_id']:
                    newUserClubsStr += userClubs[j] + ','
        else:
            newUserClubsStr = ''

        # update the i'th user's clubs
        db.execute('UPDATE users SET clubsSignedUp = ? WHERE users.userId = ?', newUserClubsStr, studentAccs[i]['userId'])

        removeQuery = db.execute('DELETE FROM clubs WHERE clubs.owner = ?', session.get('user_id'))

    flash('Deleted Club!')
    return redirect(url_for('index'))

@app.route('/uploads/<filename>')
@login_required
def upload(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.errorhandler(413)
def too_large(e):
    return apology('File is too large!')

def validate_image(stream):
    header = stream.read(512)
    stream.seek(0)
    format = imghdr.what(None, header)
    if not format:
        return None
    return '.' + (format if format != 'jpeg' else 'jpg')

def checkPhotos(owner):
    files = os.listdir(app.config['UPLOAD_FOLDER'])

    extensions = ['.png', '.jpg', '.gif']

    # check if photo file exists already
    for file in files:
        # if the file name == club id
        for i in range(len(extensions)):
            # only prints the current club's (logged in) photo
            if file == str(owner) + extensions[i]:
                return file
    return False