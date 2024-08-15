import joblib
from flask import Flask, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
import numpy as np

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/about')
def about():
    return render_template("about.html")


@app.route('/help')
def help():
    return render_template("help.html")


@app.route('/terms')
def terms():
    return render_template("tc.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('dashboard'))

    return render_template("login.html", form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect("/login")
    return render_template('signup.html', form=form)


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/disindex")
def disindex():
    return render_template("disindex.html")


@app.route("/cancer")
@login_required
def cancer():
    return render_template("cancer.html")


@app.route("/diabetes")
@login_required
def diabetes():
    return render_template("diabetes.html")


@app.route("/heart")
@login_required
def heart():
    return render_template("heart.html")


@app.route("/kidney")
@login_required
def kidney():
    return render_template("kidney.html")


@app.route("/liver")
@login_required
def liver():
    return render_template("liver.html")


def ValuePredictor(to_predict_list, size, model_path):
    try:
        to_predict = np.array(to_predict_list).reshape(1, size)
        loaded_model = joblib.load(model_path)
        result = loaded_model.predict(to_predict)
        return result[0]
    except Exception as e:
        print(f"Error during prediction: {e}")
        return None


@app.route('/predictcancer', methods=["POST"])
def predictcancer():
    if request.method == "POST":
        to_predict_list = list(request.form.to_dict().values())
        to_predict_list = list(map(float, to_predict_list))
        if len(to_predict_list) == 5:
            result = ValuePredictor(to_predict_list, 5, r'C:\Users\99220\Desktop\RISK\cancer_model.pkl')
            if result is None:
                prediction = "Error in prediction"
                high_risk = False
            elif int(result) == 1:
                prediction = "Patient has a high risk of Breast Cancer"
                high_risk = True
            else:
                prediction = "Patient has a low risk of Breast Cancer"
                high_risk = False

            return render_template("cancer_result.html", prediction_text=prediction, high_risk=high_risk)


@app.route('/predictdiabetes', methods=["POST"])
def predictdiabetes():
    if request.method == "POST":
        to_predict_list = list(request.form.to_dict().values())
        to_predict_list = list(map(float, to_predict_list))
        if len(to_predict_list) == 6:
            result = ValuePredictor(to_predict_list, 6, r'C:\Users\99220\Desktop\RISK\diabetes_model.pkl')
            if result is None:
                prediction = "Error in prediction"
                high_risk = False
            elif int(result) == 1:
                prediction = "Patient has a high risk of Diabetes Disease"
                high_risk = True
            else:
                prediction = "Patient has a low risk of Diabetes Disease"
                high_risk = False

            return render_template("diab_result.html", prediction_text=prediction, high_risk=high_risk)


@app.route('/predictheart', methods=["POST"])
def predictheart():
    if request.method == "POST":
        to_predict_list = list(request.form.to_dict().values())
        to_predict_list = list(map(float, to_predict_list))
        if len(to_predict_list) == 7:
            result = ValuePredictor(to_predict_list, 7, r'C:\Users\99220\Desktop\RISK\heart_model.pkl')
            if result is None:
                prediction = "Error in prediction"
                high_risk = False
            elif int(result) == 1:
                prediction = "Patient has a high risk of Heart Disease"
                high_risk = True
            else:
                prediction = "Patient has a low risk of Heart Disease"
                high_risk = False

            return render_template("heart_result.html", prediction_text=prediction, high_risk=high_risk)


@app.route('/predictkidney', methods=["POST"])
def predictkidney():
    if request.method == "POST":
        to_predict_list = list(request.form.to_dict().values())
        to_predict_list = list(map(float, to_predict_list))
        if len(to_predict_list) == 7:
            result = ValuePredictor(to_predict_list, 7, r'C:\Users\99220\Desktop\RISK\kidney_model.pkl')
            if result is None:
                prediction = "Error in prediction"
                high_risk = False
            elif int(result) == 1:
                prediction = "Patient has a high risk of Kidney Disease"
                high_risk = True
            else:
                prediction = "Patient has a low risk of Kidney Disease"
                high_risk = False

            return render_template("kidney_result.html", prediction_text=prediction, high_risk=high_risk)


@app.route('/predictliver', methods=["POST"])
def predictliver():
    if request.method == "POST":
        to_predict_list = list(request.form.to_dict().values())
        to_predict_list = list(map(float, to_predict_list))
        if len(to_predict_list) == 7:
            result = ValuePredictor(to_predict_list, 7, r'C:\Users\99220\Desktop\RISK\liver_model.pkl')
            if result is None:
                prediction = "Error in prediction"
                high_risk = False
            elif int(result) == 1:
                prediction = "Patient has a high risk of Liver Disease"
                high_risk = True
            else:
                prediction = "Patient has a low risk of Liver Disease"
                high_risk = False

            return render_template("liver_result.html", prediction_text=prediction, high_risk=high_risk)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == "__main__":
    app.run(debug=True)
