from flask import Blueprint, request, render_template, redirect, url_for, flash
from flask_login import login_required, login_user, logout_user

from app.models import Cargo
from app.utils import validators
from app.services import auth_service

auth_bp = Blueprint("auth", __name__)



@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    email = request.form.get('emailForm')
    senha = request.form.get('senhaForm')

    if not validators.validar_email(email):
        flash('E-mail inválido', 'danger')
        return render_template('login.html', form_data=request.form)

    usuario = auth_service.buscar_usuario(email)

    if usuario == None:
        flash('E-mail ou senha incorretos', 'danger')
        return render_template('login.html', form_data=request.form)
    
    if not auth_service.verif_corresp_senha(usuario, senha):
        flash('E-mail ou senha incorretos', 'danger')
        return render_template('login.html', form_data=request.form)
        
    login_user(usuario)
    return redirect(url_for('main.home'))
    


@auth_bp.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    cargos = Cargo.query.order_by(Cargo.nome).all()

    if request.method == 'GET':
        return render_template('cadastro.html', cargos=cargos)
    
    #dados
    nome_completo = request.form.get('nome_completoForm')
    nome_usuario = request.form.get('nome_usuarioForm')
    email = request.form.get('emailForm')
    tipo = request.form.get('tipoForm')

    senha = request.form.get('senhaForm')
    confirmacao_senha = request.form.get('confirmacao_senhaForm')

    id_cargo_form = request.form.get('cargoForm')
    especializacao = request.form.get('especializacaoForm')
    lattes = request.form.get('lattesForm')


    #validação
    if not validators.validar_tipo(tipo):
        flash('Tipo de usuário inválido', 'danger')
        return render_template('cadastro.html', form_data=request.form, cargos=cargos)

    id_cargo = None

    if tipo == 'servidor':
        try:
            id_cargo = int(id_cargo_form)
        except(TypeError, ValueError):
            flash('Selecione um cargo válido,', 'danger')
            return render_template('cadastro.html', form_data=request.form, cargos=cargos)

    if tipo == 'servidor':
        if not especializacao or  not especializacao.strip():
            flash('Informe sua especialização.','danger')
            return render_template('cadastro.html', form_data=request.form, cargos=cargos)

        if not validators.validar_lattes(lattes):
            flash('Informe um link do currículo lattes válido.', 'danger')
            return render_template('cadastro.html', form_data=request.form, cargos=cargos)
        

    if not validators.validar_usuario(nome_usuario):
        flash('O nome de usuário não deve ter espaços.', 'danger')
        return render_template('cadastro.html', form_data=request.form, cargos=cargos)

    if not validators.validar_email(email):
        flash('E-mail inválido', 'danger')
        return render_template('cadastro.html', form_data=request.form, cargos=cargos)

    if auth_service.buscar_usuario(email):
        flash('E-mail já cadastrado', 'danger')
        return render_template('cadastro.html', form_data=request.form, cargos=cargos)
        
    if not validators.validar_senha(senha):
        flash('A senha deve ter no mínimo 8 caracteres e não pode ter espaços', 'danger')
        return render_template('cadastro.html', form_data=request.form, cargos=cargos)

    if not validators.validar_confirm_senha(senha, confirmacao_senha):
        flash('As senhas devem ser correspondentes', 'danger')
        return render_template('cadastro.html', form_data=request.form, cargos=cargos)
        
    #cadastro
    try:
        novo_usuario = auth_service.cadastrar_usuario(nome_completo, nome_usuario, email, senha, tipo, id_cargo, especializacao, lattes)

    except ValueError as e:
        flash(str(e), 'danger')
        return render_template('cadastro.html', form_data=request.form, cargos=cargos)

    except Exception as e:
        print(e)
        flash('Não foi possível realizar cadastro.', 'danger')
        return render_template('cadastro.html', form_data=request.form, cargos=cargos)
        
    login_user(novo_usuario)

    return redirect(url_for('main.home'))


@auth_bp.route('/logout')
@login_required
def logout():  
    logout_user()
    return redirect(url_for('main.inicio'))