from flask import Blueprint, request, render_template, redirect, url_for, flash, abort
from flask_login import login_required, current_user

from app.extensions import db
from app.models import Atividade, Curso, Classe_Tag
from app.services import storage_service, activities_service, file_service

activities_bp = Blueprint('activities', __name__)



@activities_bp.route('/publicar', methods = ['GET', 'POST'])
@login_required
def publicar():
    cursos = Curso.query.all()
    classes = Classe_Tag.query.all()

    if request.method == 'GET':
        return render_template('publicar.html', cursos=cursos, classes=classes)
    
    try: #tira o elif pq só tem POST como segunda opção
        #---- dados ----
        arquivo = request.files.get('arquivoForm')
        if not arquivo:
            raise ValueError('Arquivo não enviado')
        dados_arquivo = storage_service.upload_arquivo(arquivo)

        titulo = request.form.get('tituloForm')
        descricao = request.form.get('descricaoForm')
        id_materia = request.form.get('materiaForm')
        ids_tags = request.form.getlist('tagsForm')

        #--- serviços ---
        nova_atividade = activities_service.criar_atividade(titulo, descricao, id_materia, ids_tags, current_user.id_usuario)
        id_atividade = nova_atividade.id_atividade
        file_service.registrar_arquivo(dados_arquivo, id_atividade)

        db.session.commit()
        flash('Atividade publicada com sucesso.', 'success')
        return redirect(url_for('user.perfil'))

    except ValueError as e:
        flash(str(e), 'warning')
        return redirect(url_for('activities.publicar', form_data=request.form))
    
    except Exception as e:
        db.session.rollback()
        if dados_arquivo and dados_arquivo.get('public_id'):
            storage_service.delete_cloudinary(dados_arquivo['public_id'])
        flash('Erro interno no servidor', 'danger')
        return redirect(url_for('activities.publicar', form_data=request.form))



@activities_bp.route('/delete/atividade/<int:id>', methods = ['POST'])
@login_required
def excluir_atividade(id):
    atividade = Atividade.query.get_or_404(id)
    id_usuario = current_user.id_usuario

    try:
        activities_service.excluir_atividade(id_usuario, atividade)
        flash('Atividade excluida com sucesso.', 'success')
    
    except PermissionError:
        abort(403)

    except Exception:
        flash('Não foi possível excluir a atividade', 'danger')

    return redirect(url_for('user.perfil'))



@activities_bp.route('/detalhes/<int:id>')
def detalhes_atividade(id):
    atividade = Atividade.query.get_or_404(id)
    return render_template('detalhes.html', atividade=atividade)