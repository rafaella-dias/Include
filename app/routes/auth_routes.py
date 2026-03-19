import re

from flask import Blueprint, request, render_template, redirect, url_for, flash
from flask_login import login_required, login_user, logout_user

from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db
from app.models import Usuario


auth_bp = Blueprint("auth", __name__)


regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    elif request.method == 'POST':
        email = request.form.get('emailForm')
        senha = request.form.get('senhaForm')

        if not re.match(regex, email):
            flash('E-mail inválido', 'danger')
            return render_template('login.html', form_data=request.form)
        
        usuario = Usuario.query.filter_by(email=email).first()

        if not usuario or not check_password_hash(usuario.senha, senha):
            flash('E-mail ou senha incorretos', 'danger')
            return render_template('login.html', form_data=request.form)
        
        login_user(usuario)
        return redirect(url_for('main.home'))
    

@auth_bp.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'GET':
        return render_template('cadastro.html')
    
    elif request.method == 'POST':
        nome_completo = request.form.get('nome_completoForm')
        nome_usuario = request.form.get('nome_usuarioForm')
        email = request.form.get('emailForm')
        senha = request.form.get('senhaForm')
        confirmacao_senha = request.form.get('confirmacao_senhaForm')

        if ' ' in nome_usuario:
            flash('O nome de usuário não deve ter espaços.')
            return render_template('cadastro.html', form_data=request.form)

        if not re.match(regex, email):
            flash('E-mail inválido', 'danger')
            return render_template('cadastro.html', form_data=request.form)

        if Usuario.query.filter_by(email=email).first():
            flash('E-mail já cadastrado', 'danger')
            return render_template('cadastro.html', form_data=request.form)
        
        if len(senha) < 8 or ' ' in senha:
            flash('A senha deve ter no mínimo 8 caracteres e não pode ter espaços', 'danger')
            return render_template('cadastro.html', form_data=request.form)

        if senha != confirmacao_senha:
            flash('As senhas devem ser iguais', 'danger')
            return render_template('cadastro.html', form_data=request.form)
        
        descricao = None
        tipo = 'usuario'
        public_id = None
        foto_url = None

        senha_hash = generate_password_hash(senha)

        novo_usuario = Usuario(nome_completo=nome_completo, 
                               nome_usuario=nome_usuario, 
                               email=email, 
                               descricao=descricao, 
                               senha=senha_hash, 
                               tipo=tipo, 
                               public_id=public_id, 
                               foto_url=foto_url)
        db.session.add(novo_usuario)
        db.session.commit()

        login_user(novo_usuario)

        return redirect(url_for('main.home'))


@auth_bp.route('/logout')
@login_required
def logout():  
    logout_user()
    return redirect(url_for('main.inicio'))