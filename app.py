# Developed by linkedin.com/in/alfonso-barrera-mora-52684393

from flask import Flask,request, abort, send_file, escape, render_template, session, redirect, url_for, flash, Markup, json
import sqlite3
import json
from collections import Counter
import six
import os #Impot OS utilities
import re #Regular Expressions
from flask_sqlalchemy import SQLAlchemy #Implement DB Controller
import bcrypt #Implement bcrypt for password hashing
from datetime import datetime
from werkzeug.exceptions import HTTPException
from flask_bcrypt import Bcrypt


app = Flask(__name__) #Flask object
#mysql://username:password@server/db #Connection String
SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://rms:rms.password@localhost/rms'   #mysql cnf
app.config['SQLALCHEMY_DATABASE_URI'] =SQLALCHEMY_DATABASE_URI                      #mysql cnf
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rms.sqlite3' #sqlite configuration
app.config['SECRET_KEY'] = "random string"
db = SQLAlchemy(app)
bcrypt=Bcrypt(app) #Alfonso: Bcrypt is the chosen library to hash users passwords.


class MemberStatus:
	Active=True
	Inactive=False
class MemberRole:
	Admin=2
	General=1
	Guest=0

class Members(db.Model):
    id = db.Column('member_id', db.Integer, primary_key = True)
    fname = db.Column(db.String(100))
    lname=db.Column(db.String(100))
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(200)) 
    salt = db.Column(db.String(200)) 
    role = db.Column(db.String(50))
    status = db.Column(db.String(50))
    lastlogin = db.Column(db.String(100))
    timeslogged = db.Column(db.Integer())
    trackerkey = db.Column(db.Integer())

class Application(db.Model):
	id=db.Column('application_id', db.Integer, primary_key=True)
	sap_id = db.Column(db.String(100))
	experience=db.Column(db.String(100))
	subexperience=db.Column(db.String(100))
	name=db.Column(db.String(200) , unique=True)
	
class ProjectStatus(db.Model):
	id=db.Column('status_id', db.Integer, primary_key=True)
	projectid = db.Column(db.String(10))
	subject=db.Column(db.String(100))
	object=db.Column(db.String(100))
	date=db.Column(db.String(200))


class Project(db.Model):
    id=db.Column('project_id', db.Integer, primary_key=True)
    appid = db.Column(db.String(15))
    name=db.Column(db.String(200) , unique=True)
    description = db.Column(db.String(2000))
    scope = db.Column(db.String(2000))
    assessID = db.Column(db.String(15))
    tracker_id = db.Column(db.String(15))
    urls = db.Column(db.String(2000))
    githubs = db.Column(db.String(2000))
    fortifys = db.Column(db.String(2000))
    priority = db.Column(db.String(10))
    type = db.Column(db.String(20))
    engineer = db.Column(db.String(30))
    deadline = db.Column(db.String(30))
    status= db.Column(db.String(30))

def register():
    bpy.utils.register_module(__name__)

def unregister():
    bpy.utils.unregister_module(__name__)

@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html'), 404

@app.errorhandler(HTTPException)
def handle_exception(e):
    """Return JSON instead of HTML for HTTP errors."""
    # start with the correct headers and status code from the error
    response = e.get_response()
    # replace the body with JSON
    response.data = json.dumps({
        "code": e.code,
        "name": e.name,
        "description": e.description,
    })
    response.content_type = "application/json"
    return response
	
@app.after_request
def add_header(response):
	response.cache_control.no_store = True
	if 'Cache-Control' not in response.headers:
		response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
		response.headers["Pragma"] = "no-cache"
		response.headers["Expires"] = "0"
		response.headers['Cache-Control'] = 'public, max-age=0'
	return response
	

@app.route('/', methods=['GET', 'POST'])
def root():
    return redirect(url_for('login'))
    
    
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method=='GET':
        return render_template('login.html')
    if request.method=='POST':
        try:
            if not request.form['username']: 
                flash('Error: Missing Username', 'Error')
                return render_template('login.html')
            if not request.form['password']:
                flash('Error: Missing Password', 'Error')
                return render_template('login.html')
            else:#data
                user=request.form['username']
                rqstPass=request.form['password']
                #Verify username/password
                member=Members()
                appUser=member.query.filter_by(username=user).first() #Limit the search to the first record.
                if appUser is None: # No user found.
                    flash('Username {} is not a valid user. Please Sign Up'.format(user), 'Error') #Flask HTML-escape automatically, unless directed. 
                    return render_template('login.html')
                if appUser.status:
                    if bcrypt.check_password_hash(appUser.password, rqstPass): # returns True if the hash values matches.
                        session['fname']=appUser.fname
                        session['lname']=appUser.lname
                        session['username']=appUser.username
                        session['userid']=appUser.id
                        session['role']=appUser.role
                        session['logged_in']=True
                        appUser.lastlogin=str(datetime.now())
                        usercounter=int(appUser.timeslogged)
                        usercounter=usercounter+1
                        appUser.timeslogged=str(usercounter)
                        db.session.commit()
                        return redirect(url_for('projects'))
                    else:
                        flash('Wrong Credentials', 'Error')
                        return render_template('login.html')
                else:
                    flash('The user <b>{}</b> is Inactive. Please contact System Administrator'.format(user), 'Error')
                    return render_template('login.html') 
                return render_template('login.html')
        except Exception as e:
            flash(str(e), 'Error')               
            return render_template('login.html')

@app.route('/home', methods=['GET'])
def home():
	if session.get('logged_in'):
		return render_template('home.html')
	else:
		return redirect(url_for('login'))


@app.route('/SignUp', methods=['GET', 'POST'])
def SignUp():
    if request.method=='POST':
        if not request.form['fname'] or not request.form['username'] or not request.form['password'] or not request.form['lname'] :
            flash('Please enter all the fields in the Sign Up form.', 'Error')
            return render_template('login.html')
        else: #Verify is the user exists
            user=request.form['username']
            members=Members()
            passwordPolicy=password_check(request.form['password'])
            if members.query.filter_by(username=user).all():
                flash('The user {} is registered already. Please contact the System Administrator'.format(user), 'Error')
                return render_template('login.html')
                
            if passwordPolicy['password_ok']:
                members.fname = request.form['fname']
                members.lname = request.form['lname'] 
                members.username = request.form['username']
                members.password = bcrypt.generate_password_hash(request.form['password'])
                members.salt = None
                members.trackerkey = request.form['trackerkey']
                members.role=MemberRole.Guest
                members.status=MemberStatus.Inactive
                members.timeslogged=0
                members.lastlogin=str(datetime.now())
                
                db.session.add(members)
                db.session.commit()
                flash('User Registration Successfully. Please contact the SysAdmin to get your account activated.', 'Message')
                return redirect(url_for('login'))
            else: 
                flash('The chosen password is weak. Please try again.', 'Error')
                return redirect(url_for('login'))
    
    else:
        return redirect(url_for('login'))

def password_check(password):
    """
    Verify the strength of 'password'
    Returns a dict indicating the wrong criteria
    A password is considered strong if:
        8 characters length or more
        1 digit or more
        1 symbol or more
        1 uppercase letter or more
        1 lowercase letter or more
    """

    # calculating the length
    length_error = len(password) < 8

    # searching for digits
    digit_error = re.search(r"\d", password) is None

    # searching for uppercase
    uppercase_error = re.search(r"[A-Z]", password) is None

    # searching for lowercase
    lowercase_error = re.search(r"[a-z]", password) is None

    # searching for symbols
    symbol_error = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None

    # overall result
    password_ok = not ( length_error or digit_error or uppercase_error or lowercase_error or symbol_error )

    return {
        'password_ok' : password_ok,
        'length_error' : length_error,
        'digit_error' : digit_error,
        'uppercase_error' : uppercase_error,
        'lowercase_error' : lowercase_error,
        'symbol_error' : symbol_error,
    }

@app.route('/logout', methods=['GET', 'POST'])
def logout():
	if session.get('logged_in'):
		session.pop('userid', None)
		session.pop('name', None)
		session.pop('username', None)
		session.pop('role', None)
		session.pop('status', None)
		session.pop('logged_in', False)
	return redirect(url_for('login'))
		

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if session.get('logged_in'):
        if session['role']==MemberRole.Admin:
            members=Members()
            users=members.query.all()
            return render_template('admin.html',users=users)
        else:
            referrer = request.referrer
            abort(403)
    else:
        return redirect(url_for('login'))

@app.route('/admin/update/user/<userid>', methods=['GET', 'POST'])
def update_user(userid):
    if session.get('logged_in'):
        if request.method=='GET':
            if session['role']==MemberRole.Admin or session['username']=='alfonso':
                members=Members()
                user=members.query.filter_by(id=userid).first()
                return render_template('admin-update-user.html',user=user, MemberRole=MemberRole(), MemberStatus=MemberStatus())
            else:
                return redirect(url_for('home'))
        if request.method=='POST':
            if session['role']==MemberRole.Admin or session['username']=='alfonso':
                member=db.session.query(Members).get(userid)
                member.fname = request.form['fname'] 
                member.lname = request.form['lname'] 
                member.username = request.form['username']
                member.trackerkey = request.form['trackerkey']
                member.role = request.form['role']
                member.status = request.form['status']
                if session['username']==request.form['username']:
                    session['role']=request.form['role']
                    session['status']=request.form['status']
                db.session.commit()    
                    
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('home'))
    else:
        return redirect(url_for('login'))
@app.route('/profile/user/<userid>', methods=['GET', 'POST'])
def update_profile(userid):
    if session.get('logged_in'):
        userid=int(userid)
        if request.method=='GET':
            if session['userid']==userid: # Check if the same user is trying to update his own session
                members=Members()
                user=members.query.filter_by(id=session['userid']).first()
                return render_template('profile-update-user.html',user=user, MemberRole=MemberRole(), MemberStatus=MemberStatus())
            else:
                abort(403)

        if request.method=='POST':
            members=Members()
            user=members.query.filter_by(id=session["userid"]).first() 
            if session["userid"]==userid: #Check if the same user is trying to update his own session
                member=db.session.query(Members).get(userid)
                member.fname = request.form['fname']
                member.lname = request.form['lname']  
                member.username = request.form['username']
                member.password = request.form['password']
                member.trackerkey = request.form['trackerkey']
                db.session.commit()
                if session['username']==request.form['username']:
                    session['username']=request.form['username']
                    session['fname']=request.form['fname']
                    session['lname']=request.form['lname']
                return render_template('profile-update-user.html',user=user, MemberRole=MemberRole(), MemberStatus=MemberStatus())
            else:
                flash('Security Violation: Access Control Policy activated. Hacked attampt logged.', 'Error')
                return render_template('profile-update-user.html',user=user, MemberRole=MemberRole(), MemberStatus=MemberStatus())
    else:
        return redirect(url_for('login'))


@app.route('/projects', methods=['GET', 'POST'])
def projects():
	if session.get('logged_in'):
		project=Project()
		projects=project.query.all()
		return render_template('projects.html',projects=projects)
	else:
		return redirect(url_for('login'))
		
@app.route('/projectDashboard/projectid/<projectid>', methods=['GET', 'POST'])
def projectDashboard(projectid):
	if session.get('logged_in'):
		if request.method=='GET':	
			try:
				project=Project()
				project=project.query.filter_by(id=projectid).first()
				return render_template('projectDashboard.html',project=project)
			except Exception as e:
				print (e)
				raise
		if request.method=='POST':
			print ('POST METHOD in projectDashboard on project {}'.format(projectid))
			return 'POST METHOD in projectDashboard on project {}'.format(projectid)
	else:
		return redirect(url_for('login'))
		
		
@app.route('/project_add_defect/projectid/<projectid>', methods=['GET', 'POST'])
def project_add_defect(projectid):
	if session.get('logged_in'):
		if request.method=='GET':	
			return render_template('project_add_defect.html', projectid=projectid)
		if request.method=='POST':
			print ('POST METHOD in projectDashboard on project {}'.format(projectid))
			return 'POST METHOD in projectDashboard on project {}'.format(projectid)
	else:
		return redirect(url_for('login'))
		
@app.route('/project_import_45_defects/projectid/<projectid>', methods=['GET', 'POST'])
def project_import_45_defects(projectid):
	if session.get('logged_in'):
		if request.method=='GET':	
			return render_template('project_import_fortify_defects.html', projectid=projectid)
		if request.method=='POST':
			print ('POST METHOD in project_import_45_defects on project {}'.format(projectid))
			return 'POST METHOD in project_import_45_defects on project {}'.format(projectid)
	else:
		return redirect(url_for('login'))

		
		
@app.route('/project_manage_defects/projectid/<projectid>', methods=['GET', 'POST'])
def project_manage_defects(projectid):
	if session.get('logged_in'):
		if request.method=='GET':	
			return render_template('project_manage_defects.html', projectid=projectid)
		if request.method=='POST':
			print ('POST METHOD in project_import_45_defects on project {}'.format(projectid))
			return 'POST METHOD in project_import_45_defects on project {}'.format(projectid)
	else:
		return redirect(url_for('login'))
		
		
@app.route('/project_create_sec_report/projectid/<projectid>', methods=['GET', 'POST'])
def project_create_sec_report(projectid):
		return redirect(url_for('login'))
		
@app.route('/project_update/projectid/<projectid>', methods=['GET', 'POST'])
def project_update(projectid):
		return redirect(url_for('login'))
		
@app.route('/project_delete/projectid/<projectid>', methods=['GET', 'POST'])
def project_delete(projectid):
		return redirect(url_for('login'))
        
@app.route('/applications', methods=['GET', 'POST'])
def applications():
	if session.get('logged_in'):
		try:
			applications=Application()
			applications=applications.query.all()
		except Exception as e:
			print (e)
			raise
				
		return render_template('applications.html', applications=applications)
	else:
		return redirect(url_for('login'))
		
@app.route('/addNewApplication', methods=['GET', 'POST'])
def addNewApplication():
    if session.get('logged_in'):
        if request.method=='POST':
            try:
                sap_id=request.form['sap_id']
                experience=request.form['experience']
                subexperience=request.form['sub_experience']
                name=request.form['name']

                application=Application()
                application.sap_id=str(sap_id)
                application.experience=experience
                application.subexperience=subexperience
                application.name=name

                db.session.add(application)
                db.session.commit()

                return redirect(url_for('applications'))
            except Exception as e:
                print (e)
                raise
            
        else:
            return redirect(url_for('applications'))
    else:
        return redirect(url_for('login'))
	
@app.route('/addNewProject/appid/<appid>', methods=['GET', 'POST'])
def addNewProject(appid):
    if session.get('logged_in'):
        if request.method=='GET':
            try:
                application=db.session.query(Application).get(appid)
                return render_template('project_add_new_project.html', application=application)
            except Exception as e:
                print (e)
                raise
            
        if request.method=='POST':
            project = Project()
            project.appid = appid
            project.name = request.form['name']
            project.description = request.form['description']
            project.scope = request.form['scope']
            project.assessID = request.form['assessID']
            project.tracker_id = request.form['tracker_id']
            project.urls = request.form['urls']
            project.githubs = request.form['githubs']
            project.fortifys = request.form['fortifys']
            project.priority = request.form['priority']
            project.type = request.form['type']
            project.engineer = session['userid']
            project.deadline = 'Undefined'
            project.status = 'Draft'
            
            db.session.add(project)
            db.session.commit()
    
            return redirect(url_for('applications'))
    
    else:
        return redirect(url_for('login'))



if __name__=="__main__":
	#app.secret_key=os.urandom(32) #Needed for HTTPS
	db.create_all()
	app.run(host='0.0.0.0', debug = True, port=5000)
	#app.run(ssl_context='adhoc', host='0.0.0.0', port=5000)
