from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_bcrypt import Bcrypt

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrpt = Bcrypt()


login_manager = LoginManager()
login_manager.init(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB.
# db.create_all()

# def __repr__(self):
#     return '<User %r>' % self username
#
# class login_form(FlaskForm):
#     email = StringField(validators=[InputRequired(), Email(), Length(1, 64)])
#     pwd = PasswordField(validators=[InputRequired(), Length(min=8, max=72)])
#     # Placeholder labels to enable form rendering
#     username = StringField(
#         validators=[Optional()]
#     )
# class AuthUser:
#     @cached_property
#     def value(self):
#
#         return 42
# e = AuthUser()
# e.value
# e.value
# e.value
# del e.value
# def validate_email(self, email):
#     if User.query.filter_by(email=email.data).first():
#         raise ValidationError('Email already registered!')
#
# def validate_uname(self, uname):
#     if User.query.filter_by(username=username.data).first():
#         raise ValidationError('Username already taken!')

# if form.validate_on_submit():
#         try:
#             user = User.query.filter_by(email=form.email.data).first()
#             if check_password_hash(user.pwd, form.pwd.data):
#                 login_user(user)
#                 return redirect(url_for('index'))
#             else:
#                 flash("Invalid Username or password!", "danger")
#         except Exception as e:
            # flash(e, "danger")


@app.route('/', methods=['GET', 'POST'])
def home():
    return render_template("index.html",logged_in=current_user.is_authenciated) #title='home')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':


        if User.query.filter_by(email=request.form.get('email')).first():
            flash('You have already signed up with that email, log in stead!')
            return redirect(url_for('login'))

        hash_and_salt = generate_password_hash(
            request.form.get('password'),
            method='phbkd2:sha256',
            #  werkzeug.security.generate_password_hash(password=request.form.get('user_password'), method='sha256', salt_length=8)
            salt_length=8
        )

        new_user = User(
            email=request.form.get('email'),
            name=request.form.get('name'),
            password=request.form.get('password'),
        )
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('secrets'))

    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login/<user>', methods=['GET', 'POST'])
# @login_manager.user_loader
def login(user):
    # check_password = True
    # error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password= request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if not user:
            flash('that email does not exist, please try again')
            return redirect(url_for('login'))

        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('secrets'))


        # if request.form['username'] != 'username' or \
        #         request.form['password'] != 'password':
        #         error = 'Invalid credentials'
        #     else:
        #         flash('you were successfuly logged in')





        email = requets.form.get('email')
        password = request.form.get('password')


        user = User.query.filter_by(email=email).first()


        if check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('secrets'))
    # form = LoginForm()
    # if form.validate_on_submit():
    #     login_user(user)
    #
    #     flask.flash('successful logged in')
    #     next = flask.request.args.get('next')
    #     if not url_has_allowed_host_and_scheme(next, request.host):
    #         return flask.abort(400)
    #         return flask.redirect(next or flask.url_for('index'))
    return flask.render_template('login.html', logged_in=current_user_is_authenticated) #error=error) #, form=form)


@app.route('/secrets', methods=['GET', 'POST'])
@login_required
def secrets():
    print(current_user.name)
    # download = send_from_directory()
    return render_template("secrets.html", name=current_user.name, logged_in=True)


@app.route('/logout', methods=['GET', 'POST'])
# @login_reqquired
def logout():
    logout_user()
    return redirect()



@app.route('/download/<path:cheat_sheet>')
def download(cheat_sheet):
    return send_from_directory(app.config['files'],
        cheat_sheet, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
