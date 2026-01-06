from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, login_user, login_required, logout_user
from db import db
from models import Usuario
import hashlib


app = Flask(__name__)
app.secret_key = 'senhasecreta'
login_manager = LoginManager(app)
login_manager.login_view = 'login'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///DatabaseInclude.db'
db.init_app(app)


def hash(txt):
    hash_obj = hashlib.sha256(txt.encode('utf-8'))
    return hash_obj.hexdigest()


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

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'GET':
        return render_template('cadastro.html')
    
    elif request.method == 'POST':
        nome = request.form['nomeForm']
        senha = request.form['senhaForm']

        novo_usuario = Usuario(nome=nome, senha=hash(senha))
        db.session.add(novo_usuario)
        db.session.commit()

        login_user(novo_usuario)

        return redirect(url_for('home'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    elif request.method == 'POST':
        nome = request.form['nomeForm']
        senha = request.form['senhaForm']

        usuario_logado = db.session.query(Usuario).filter_by(nome=nome, senha=hash(senha)).first()

        if not usuario_logado:
            return 'Nome ou senha incorretos.'
        
        login_user(usuario_logado)
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

