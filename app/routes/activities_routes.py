from flask import Blueprint, request, render_template, redirect, url_for, flash, abort
from flask_login import login_required, current_user

from werkzeug.utils import secure_filename
import cloudinary.uploader

from app.extensions import db
from app.models import Atividade, Arquivo, Materia, Curso, Tag, Classe_Tag
from app.utils.upload import validar_arquivo

activities_bp = Blueprint('activities', __name__)


@activities_bp.route('/delete/atividade/<int:id>', methods = ['POST'])
@login_required
def excluir_atividade(id):
    atividade = Atividade.query.get_or_404(id)

    if atividade.id_usuario != current_user.id_usuario:
        abort(403)

    try: 
        for arquivo in atividade.arquivos:
            cloudinary.uploader.destroy(arquivo.public_id)

        db.session.delete(atividade)
        db.session.commit()

        flash('Atividade excluida com sucesso', 'success')

    except Exception as e:
        db.session.rollback()
        print(e)
        flash('Não foi possível excluir a atividade', 'danger')

    return redirect(url_for('user.perfil'))

@activities_bp.route('/publicar', methods = ['GET', 'POST'])
@login_required
def publicar():
    cursos = Curso.query.all()
    classes = Classe_Tag.query.all()

    if request.method == 'GET':
        return render_template('publicar.html', cursos=cursos, classes=classes)
    
    try: #tira o elif pq só tem POST como segunda opção
        titulo = request.form.get('tituloForm')
        descricao = request.form.get('descricaoForm')
        id_materia = request.form.get('materiaForm')
        ids_tags = request.form.getlist('tagsForm')
        materia = Materia.query.get_or_404(id_materia)
        id_curso = materia.id_curso

        nova_atividade = Atividade(titulo=titulo,
                                   descricao=descricao, 
                                   id_curso=id_curso, 
                                   id_materia=id_materia, 
                                   id_usuario=current_user.id_usuario )
        db.session.add(nova_atividade)
        db.session.flush()

        for id_tag in ids_tags:
            tag = Tag.query.get(id_tag)
            nova_atividade.tags.append(tag)

        arquivo = request.files.get('arquivoForm')
        
        valido, resultado = validar_arquivo(arquivo)

        if not valido:
            raise ValueError(resultado)

        nome = secure_filename(arquivo.filename)
        tipo = arquivo.mimetype 
        tamanho = resultado
        id_atividade = nova_atividade.id_atividade

        response = cloudinary.uploader.upload(arquivo,
                                              folder = 'atividades',
                                              unique_filename = True,
                                              overwrite = True,
                                              )
        
        secure_url = response.get('secure_url')
        public_id = response.get('public_id')
       
        novo_arquivo = Arquivo(nome=nome, 
                               tipo=tipo, 
                               tamanho=tamanho, 
                               arquivo_url=secure_url,
                               public_id=public_id,
                               id_atividade=id_atividade)

        db.session.add(novo_arquivo)
        db.session.commit()
        flash('Atividade publicada com sucesso.', 'success')
        return redirect(url_for('user.perfil'))

    except Exception as e:
        db.session.rollback()
        flash(str(e), 'danger')
        return redirect(url_for('activities.publicar', form_data=request.form))