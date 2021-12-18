from flask import Flask
import flask_login
from flask import render_template
from tinydb import TinyDB, Query
#from database import DatabaseQueries

##Definition to run this file
app = Flask(__name__)

## Homepage
@app.route("/")
def home():
    #Button to login goes to login.html
    #Button to register goes to register.html
    return render_template("homepage.html")

## URL with /login at end
## "Login Page"
@app.route("/login")
def login():
    #Views login API
    #Test login message -- acces {{login_message}} in HTML file
    login_message = "Login Message Test"
    return render_template('login.html', login_message=login_message)

#"Registration Page"
@app.route("/register")
def register():
    #Views signup API
    #Printout username and private key
    #Allow button to return to homepage
    return render_template("register.html")

##
##
## USER HOMEPAGE SPECIFIC FOR EACH USER
##
##
@app.route('/user/<username>')
def userhome(username):
    # Find out how to properly query user to get user into
    # Get their files
    # Get thier directories

    ##  Files in directroy -- encrypted - need private key to decrypt
    ##  User homepage -- each user puts contents of file and filename in browser -- no upload
    ##  Sharing files -- user dropdown and select user
    ##  Different sections for your directory -- shared files -- public files
    ##      Shared files -- in their own directory
    ##      Public files -- in the master directory -- not encrypted?

    ##  AJAX to update page when modifiying userhomepage
    #       3 json lists for user directory / shared / public
    #       Private key decrpy update

    #In views
    #load files on homepage
    ##Save file in server
    #Load files in server
    #Delete file from server
    return render_template("userhome.html")
    
if __name__ == "__main__":
    app.run(debug=True)