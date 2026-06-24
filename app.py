import os
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
UPLOAD_FOLDER = "static/uploads"

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


ALLOWED_EXTENSIONS = {
'png',
'jpg',
'jpeg',
'pdf',
'txt',
'log'
}


def allowed_file(filename):

    return '.' in filename and \
    filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

mysql = MySQL(app)

# HOME

@app.route('/')
def home():

    if 'user_id' in session:
        return redirect('/dashboard')

    return redirect('/login')


# REGISTER

@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':

        fullname = request.form['fullname']
        email = request.form['email']
        password = request.form['password']

        cur = mysql.connection.cursor()

        cur.execute(
            "SELECT * FROM users WHERE email=%s",
            (email,)
        )

        existing_user = cur.fetchone()

        if existing_user:
            flash("Email already registered", "danger")
            return redirect('/register')

        hashed_password = generate_password_hash(password)

        cur.execute(
            """
            INSERT INTO users(fullname,email,password)
            VALUES(%s,%s,%s)
            """,
            (fullname, email, hashed_password)
        )

        mysql.connection.commit()

        flash("Registration Successful", "success")

        return redirect('/login')

    return render_template('register.html')


# LOGIN

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        email = request.form['email']
        password = request.form['password']

        cur = mysql.connection.cursor()

        cur.execute(
            "SELECT * FROM users WHERE email=%s",
            (email,)
        )

        user = cur.fetchone()

        print(user)

        if user:

            db_password = user[3]

            if check_password_hash(db_password, password):
                
                session['admin_id'] = user[0]
                session['admin_name'] = user[1]
                session['role'] = user[4]

                session['user_id'] = user[0]
                session['fullname'] = user[1]
                session['role'] = user[4] 

                flash("Login Successful", "success")

                return redirect('/dashboard')

        flash("Invalid Email or Password", "danger")

    return render_template('login.html')


# DASHBOARD

@app.route('/dashboard')
def dashboard():

    if 'user_id' not in session:
        return redirect('/login')
    
    name = session.get('fullname', 'User')
    role = session.get('role', 'user')

    return  render_template('dashboard.html', name=name, role=role)

@app.route('/report-threat', methods=['GET','POST'])
def report_threat():


    if 'user_id' not in session:
        return redirect('/login')


    if request.method=='POST':


        title=request.form['title']

        category=request.form['category']

        description=request.form['description']

        severity=request.form['severity']


        file=request.files['evidence']


        filename=None


        if file and allowed_file(file.filename):

            filename=secure_filename(file.filename)

            file.save(
            os.path.join(
            app.config['UPLOAD_FOLDER'],
            filename
            )
            )


        cur=mysql.connection.cursor()


        cur.execute(
        """
        INSERT INTO threat_reports
        (
        title,
        category,
        description,
        severity,
        evidence_file,
        reported_by
        )

        VALUES(%s,%s,%s,%s,%s,%s)

        """,
        (
        title,
        category,
        description,
        severity,
        filename,
        session['user_id']
        )
        )


        mysql.connection.commit()


        flash(
        "Threat Report Submitted",
        "success"
        )


        return redirect('/my-reports')


    return render_template(
    'report_threat.html'
    )

@app.route('/my-reports')

def my_reports():


    if 'user_id' not in session:
        return redirect('/login')


    cur=mysql.connection.cursor()


    cur.execute(
    """
    SELECT * FROM threat_reports
    WHERE reported_by=%s
    """,
    (session['user_id'],)
    )


    reports=cur.fetchall()


    return render_template(
    'my_reports.html',
    reports=reports
    )

# ADMIN LOGIN

@app.route('/admin-login', methods=['GET','POST'])
def admin_login():

    if request.method == 'POST':

        email = request.form['email']
        password = request.form['password']


        cur = mysql.connection.cursor()

        cur.execute(
            "SELECT * FROM users WHERE email=%s",
            (email,)
        )

        user = cur.fetchone()


        if user:

            if user[4] == 'admin':

                if check_password_hash(user[3], password):

                    session['admin_id'] = user[0]
                    session['admin_name'] = user[1]
                    session['role'] = user[4]

                    return redirect('/admin-dashboard')


        flash("Admin Login Failed","danger")


    return render_template('admin_login.html')



# ADMIN DASHBOARD

@app.route('/admin-dashboard')
def admin_dashboard():

    if 'admin_id' not in session:
        return redirect('/admin-login')


    if session.get('role') != 'admin':
        flash("Access Denied", "danger")
        return redirect('/dashboard')


    cur = mysql.connection.cursor()


    cur.execute(
    """
    SELECT 
    threat_reports.id,
    threat_reports.title,
    threat_reports.category,
    threat_reports.severity,
    threat_reports.status,
    users.fullname

    FROM threat_reports

    JOIN users

    ON threat_reports.reported_by = users.id

    """
    )


    reports = cur.fetchall()


    return render_template(
        'admin_dashboard.html',
        reports=reports
    )


# VIEW SINGLE REPORT

@app.route('/view-report/<int:id>')
def view_report(id):

    cur=mysql.connection.cursor()


    cur.execute(
    """
    SELECT * FROM threat_reports
    WHERE id=%s
    """,
    (id,)
    )


    report=cur.fetchone()


    return render_template(
    'view_report.html',
    report=report
    )



# UPDATE STATUS

@app.route('/update-status/<int:id>', methods=['POST'])
def update_status(id):


    status=request.form['status']


    cur=mysql.connection.cursor()


    cur.execute(
    """
    UPDATE threat_reports
    SET status=%s
    WHERE id=%s
    """,
    (status,id)
    )


    mysql.connection.commit()


    return redirect('/admin-dashboard')

# LOGOUT

@app.route('/logout')
def logout():

    session.clear()

    flash("Logged Out Successfully", "success")

    return redirect('/login')


if __name__ == '__main__':
    app.run(debug=True)