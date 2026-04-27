from flask import Blueprint, request, render_template, redirect, url_for, flash
from flask_login import login_required, current_user

from werkzeug.security import generate_password_hash
import cloudinary.uploader

from app.extensions import db
from app.models import Atividade
from app.services import storage_service
from app.utils import upload, validators

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
    
    nome_completo = request.form.get('nome_completoForm')
    nome_usuario = request.form.get('nome_usuarioForm')
    descricao = request.form.get('descricaoForm')
    senha = request.form.get('senhaForm')
    confirmacao_senha = request.form.get('confirmacao_senhaForm')
    foto_perfil = request.files.get('foto_perfilForm')

    if nome_completo != current_user.nome_completo:
         current_user.nome_completo = nome_completo

    if nome_usuario != current_user.nome_usuario:
        if validators.validar_usuario(nome_usuario) == False:
            flash('O nome de usuário não deve ter espaços.', 'danger')
            return render_template('editar_perfil.html')
        current_user.nome_usuario = nome_usuario

    if descricao != current_user.descricao:
        current_user.descricao = descricao

    if senha:
        if not validators.validar_senha(senha):
            flash('A senha deve ter no mínimo 8 caracteres e não pode ter espaços', 'danger')
            return render_template('editar_perfil.html')
            
        if not validators.validar_confirm_senha(senha, confirmacao_senha):
            flash('As senhas devem ser iguais', 'danger')
            return render_template('editar_perfil.html')  
        current_user.senha = generate_password_hash(senha)


    if foto_perfil and foto_perfil.filename != '':
        if not upload.validar_imagem(foto_perfil):
            flash('Formato de imagem inválido.', 'danger')
            return render_template('editar_perfil.html')
            
        if not foto_perfil.mimetype.startswith('image/'):
            flash('O arquivo não é uma imagem válida', 'danger')
            return render_template('editar_perfil.html')
        
        foto_atual = current_user.public_id
        if foto_atual:
            storage_service.delete_cloudinary(foto_atual)

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