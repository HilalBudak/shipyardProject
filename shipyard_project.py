from flask import Flask,render_template,flash,redirect,url_for,session,logging,request
from flask_mysqldb import MySQL
from wtforms import Form,StringField,TextAreaField,PasswordField,validators
from passlib.hash import sha256_crypt

#kullanıcı kayit formu
class RegisterForm(Form):
    isim = StringField("İsim", validators=[validators.DataRequired(message="Lütfen Bu Alanı Doldurunuz.")])
    soyisim = StringField("Soy İsim", validators=[validators.DataRequired(message="Lütfen Bu Alanı Doldurunuz.")])
    tckn = StringField("TCKN", validators=[validators.Length(min = 0, max = 2,message="Geçerli bir TCKN giriniz!"),validators.DataRequired(message="Lütfen TCKN kontrol ediniz.")])
    gorevi  = StringField("Göreviniz")
    kangrubu = StringField("Kan Grubu")
    email = StringField("Email", validators=[validators.Email(message="Lütfen geçerli bir email adresi giriniz.")])
    sifre = PasswordField("Sifre", validators=[
        validators.DataRequired(message="Lütfen bir parola belirleyin."),
        validators.EqualTo(fieldname = "confirm", message="Parolanız uyuşmuyor!")
    ])
    confirm = PasswordField("Parola Doğrula")

class LoginForm(Form):
    email = StringField("Email")
    sifre = PasswordField("Şifre")

app = Flask(__name__)
app.secret_key = "himu"
app.config["MYSQL_HOST"]="127.0.0.1"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = ""
app.config["MYSQL_DB"] = "shipyard_project"
app.config["MYSQL_CURSORCLASS"] = "DictCursor"

myslq = MySQL(app)

@app.route("/register",methods = ["GET","POST"])
def register():
    form = RegisterForm(request.form)

    if request.method == "POST" and form.validate :
        isim = form.isim.data
        soyisim = form.soyisim.data
        tckn = form.tckn.data
        gorevi = form.gorevi.data
        kangrubu = form.kangrubu.data
        email = form.email.data
        sifre = sha256_crypt.encrypt(form.sifre.data)

        cursor = myslq.connection.cursor()
        sorgu = "INSERT INTO user(TCKN,Soyadi,Adi,Gorevi,KanGrubu,Email,Sifre) VALUES (%s, %s, %s, %s, %s, %s, %s)"
        cursor.execute(sorgu,(tckn,soyisim,isim,gorevi,kangrubu,email,sifre))
        myslq.connection.commit()
        cursor.close()
        flash("Başarıyla kayıt oldunuz!", "success")
        return redirect(url_for("login"))
    else:
        return render_template("register.html", form=form)

@app.route("/login", methods = ["GET", "POST"])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST':
        email = form.email.data
        password = form.sifre.data
        
        cursor = myslq.connection.cursor()
        sorgu = "Select * From user where email = %s"
        result = cursor.execute(sorgu,(email,))
        if result > 0:
            data = cursor.fetchone()
            real_password = data["Sifre"]
            if sha256_crypt.verify(password, real_password):
                flash("Giriş yapıldı..", "success")

                session["logged_in"] = True
                session["email"] = email

                return redirect(url_for("index"))
            else:
                flash("Parolanızı kontrol ediniz..", "danger")
                return redirect(url_for("login"))
        else:
            flash("Böyle bir kullanıcı bulunmuyor..","danger")
            return redirect(url_for("login"))

    return render_template("login.html", form=form)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/")
def index():
    return render_template("layout.html")
if __name__ == "__main__":
    app.run(debug=True)     #hata mesajlarini gosterir

