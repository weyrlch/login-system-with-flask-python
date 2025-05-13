from flask import Flask, request, render_template, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import redirect
import re

from config import Config

app = Flask(__name__)
app.config.from_object(Config)
app.config['SECRET_KEY'] = 'K£GN1^reR95[f*ooIT41CN+yR+887Ay;7.!@,J7Lo+*h}xSHDc'  # Necessário para Flash Messages


db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Inicializa Flask-Migrate corretamente


# Definição do modelo antes da criação do banco
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    def set_password(self, password):
        self.password = generate_password_hash(password)  # Hash seguro

    def check_password(self, password):
        return check_password_hash(self.password, password)  # Corrigido

    def __repr__(self):
        return f"<User {self.username}>"


# Criar tabelas no banco de dados, se ainda não existirem
with app.app_context():
    db.create_all()


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get('username', "")
        email = request.form.get('email', "")
        password = request.form.get('password', "")

        def validar_senha(username, senha):
            if len(senha) < 8:
                return "Erro: A senha deve ter pelo menos 8 caracteres."
            if not re.search(r"[A-Z]", senha):
                return "Erro: A senha deve conter pelo menos uma letra maiúscula."
            if not re.search(r"\d", senha):
                return "Erro: A senha deve conter pelo menos um número"
            if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", senha):
                return "Erro: A senha deve conter pelo menos um símbolo especial."
            if username.lower() in senha.lower():
                return "Erro: A senha não pode conter o nome de usuário."
            return "Senha válida"

        def validar_email(email):
            if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
                return "Erro: Email inválido"
            return "Email Valido!"


        erro_senha = validar_senha(username, password)
        erro_email = validar_email(email)

        if erro_senha != "Senha válida!":
            flash(erro_senha, "error")
        if erro_email != "Email válido!":
            flash(erro_email, "error")

        if erro_senha != "Senha válida!" or erro_email != "Email válido!":
            return render_template("register.html", username=username, email=email)

        if not username or not email or not password:
            flash("Erro: Todos os campos são obrigatórios!", "error")
            return redirect(url_for("register"))



        user = User.query.filter_by(email=email).first()
        if user:
            flash("Erro: E-mail já registrado!", "error")
            return redirect(url_for("register"))

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Usuário registrado com sucesso!")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        # Busca usuário no banco de dados
        user = User.query.filter_by(email=email).first()

        if not user or not user.check_password(password):
            flash("Erro: Email ou senha incorretos!", "error")
            return redirect(url_for("login"))
        flash("Login realizado com sucesso!", "success")
    return render_template("login.html")


@app.route("/")
def home():
    return "API is running!"


if __name__ == '__main__':
    app.run(debug=True)
