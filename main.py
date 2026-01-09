from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash,check_password_hash
from db import db
from models import Usuario
import re


app = Flask(__name__)
app.secret_key = 'senhasecreta'
login_manager = LoginManager(app)
login_manager.login_view = 'login'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///DatabaseInclude.db'
db.init_app(app)


regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'


@login_manager.user_loader
def user_loader(id):
    usuario = db.session.get(Usuario, int(id))
    return usuario


@app.route('/')
def inicio():
    return render_template('inicio.html')

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    elif request.method == 'POST':
        email = request.form['emailForm']
        senha = request.form['senhaForm']

        if not re.match(regex, email):
            flash('E-mail inválido', 'danger')
            return render_template('login.html', form_data=request.form)
        
        usuario = Usuario.query.filter_by(email=email).first()

        if not usuario or not check_password_hash(usuario.senha, senha):
            flash('E-mail ou senha incorretos', 'danger')
            return render_template('login.html', form_data=request.form)
        
        login_user(usuario)
        return redirect(url_for('home'))
    
@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'GET':
        return render_template('cadastro.html')
    
    elif request.method == 'POST':
        nome_completo = request.form['nome_completoForm']
        nome_usuario = request.form['nome_usuarioForm']
        email = request.form['emailForm']
        senha = request.form['senhaForm']
        confirmacao_senha = request.form['confirmacao_senhaForm']

        if not re.match(regex, email):
            flash('E-mail inválido', 'danger')
            return render_template('cadastro.html', form_data=request.form)

        if Usuario.query.filter_by(email=email).first():
            flash('E-mail já cadastrado', 'danger')
            return render_template('cadastro.html', form_data=request.form)
        
        if len(senha) <8 or ' ' in senha:
            flash('A senha deve ter no mínimo 8 caracteres e não pode ter espaços', 'danger')
            return render_template('cadastro.html', form_data=request.form)

        if senha != confirmacao_senha:
            flash('As senhas devem ser iguais', 'danger')
            return render_template('cadastro.html', form_data=request.form)
        
        tipo = 'usuario'

        senha_hash = generate_password_hash(senha)

        novo_usuario = Usuario(nome_completo=nome_completo, nome_usuario=nome_usuario, email=email, senha=senha_hash, tipo=tipo)
        db.session.add(novo_usuario)
        db.session.commit()

        login_user(novo_usuario)

        return redirect(url_for('home'))

@app.route('/logout')
@login_required
def logout():
    
    logout_user()
    return redirect(url_for('inicio'))

@app.route('/perfil')
@login_required
def perfil():
    return render_template('perfil.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) #remover depois!!

