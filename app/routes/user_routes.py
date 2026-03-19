from flask import Blueprint, request, render_template, redirect, url_for, flash
from flask_login import login_required, current_user

from werkzeug.security import generate_password_hash
import cloudinary.uploader

from app.extensions import db
from app.models import Atividade
from app.utils.upload import imagem_permitida

user_bp = Blueprint('user', __name__)


@user_bp.route('/perfil')
@login_required
def perfil():
    atividades = Atividade.query.filter_by(id_usuario=current_user.id_usuario).order_by(Atividade.data_publicacao.desc()).all()
    return render_template('perfil.html', atividades=atividades)


@user_bp.route('/perfil/editar', methods = ['GET', 'POST'])
@login_required
def editar_perfil():    
    if request.method == 'GET':
        return render_template('editar_perfil.html')
    
    elif request.method == 'POST':
        nome_completo = request.form.get('nome_completoForm')
        nome_usuario = request.form.get('nome_usuarioForm')
        descricao = request.form.get('descricaoForm')
        senha = request.form.get('senhaForm')
        confirmacao_senha = request.form.get('confirmacao_senhaForm')
        foto_perfil = request.files.get('foto_perfilForm')

        if nome_completo != current_user.nome_completo:
            current_user.nome_completo = nome_completo

        if nome_usuario != current_user.nome_usuario and not ' ' in nome_usuario:
            current_user.nome_usuario = nome_usuario

        if descricao and descricao != current_user.descricao:
            current_user.descricao = descricao

        if senha:
            if len(senha) < 8 or ' ' in senha:
                flash('A senha deve ter no mínimo 8 caracteres e não pode ter espaços')
                return render_template('editar_perfil.html')
            
            if senha != confirmacao_senha:
                flash('As senhas devem ser iguais')
                return render_template('editar_perfil.html')
            
            current_user.senha = generate_password_hash(senha)

        if foto_perfil and foto_perfil.filename != '':
            if not imagem_permitida(foto_perfil.filename):
                flash('Formato de imagem inválido.', 'danger')
                return render_template('editar_perfil.html')
            
            if not foto_perfil.mimetype.startswith('image/'):
                flash('O arquivo não é uma imagem válida', 'danger')
                return render_template('editar_perfil.html')
            
            if current_user.public_id:
                cloudinary.uploader.destroy(current_user.public_id)

            response = cloudinary.uploader.upload(foto_perfil, 
                                                  folder = 'perfis', 
                                                  unique_filename=True, 
                                                  overwrite=True,
                                                  transformation = [{'width':  500, 'height': 500, 'crop': 'fill'}])
            foto_url = response.get('secure_url')
            public_id = response.get('public_id')

            current_user.foto_url = foto_url
            current_user.public_id = public_id

        db.session.commit()

        flash('Dados editados com sucesso', 'success')
        return redirect(url_for('user.perfil'))
    

@user_bp.route('/delete/image/perfil', methods = ['POST'])
@login_required
def delete_image():
    try:
        cloudinary.uploader.destroy(current_user.public_id)
        current_user.public_id = None
        current_user.foto_url = None
        db.session.commit()
        
        flash('Foto de perfil removida com sucesso', 'success')

    except Exception:
        flash('Não foi possível remover a imagem', 'danger')
    
    return redirect(url_for('user.perfil'))