import json, logging

from flask import Blueprint, request, render_template, redirect, url_for, flash, abort
from flask_login import login_required, current_user

from app.extensions import db
from app.models import Material, Curso, Classe_Tag
from app.services import materials_service

materials_bp = Blueprint('materials', __name__)



@materials_bp.route('/publicar', methods = ['GET', 'POST'])
@login_required
def publicar():
    cursos = Curso.query.all()
    classes = Classe_Tag.query.all()
    cursos_json = json.dumps(materials_service.gerar_cursos_dados(), ensure_ascii=False)

    if request.method == 'GET':
        return render_template('publicar.html', cursos=cursos, classes=classes, cursos_json=cursos_json, form_data={'tagsForm': []})
    
    try: #tira o elif pq só tem POST como segunda opção
        #---- dados ----
        titulo = request.form.get('tituloForm')
        subtitulo = request.form.get('subtituloForm')
        descricao = request.form.get('descricaoForm')
        conteudo_textual = request.form.get('textoForm')
        id_curso = request.form.get('cursoForm')
        id_materia = request.form.get('materiaForm')
        id_conteudo = request.form.get('conteudoForm')
        ids_tags = request.form.getlist('tagsForm')
        id_usuario = current_user.id_usuario
        arquivos = request.files.getlist('arquivosForm')

        materials_service.publicar(titulo, subtitulo, descricao, conteudo_textual, id_curso, id_materia, id_conteudo, ids_tags, id_usuario, arquivos)
        flash('Material publicada com sucesso.', 'success')
        return redirect(url_for('user.perfil'))

    except ValueError as e:
        flash(str(e), 'warning')
        print(e)
        return render_template('publicar.html', cursos=cursos, classes=classes, cursos_json=cursos_json, form_data=request.form)
    
    except Exception as e:
        flash('Erro interno no servidor', 'danger')
        print(e)
        return render_template('publicar.html', cursos=cursos, classes=classes, cursos_json=cursos_json, form_data=request.form)



@materials_bp.route('/delete/material/<int:id>', methods = ['POST'])
@login_required
def excluir_material(id):
    material = Material.query.get_or_404(id)
    id_usuario = current_user.id_usuario

    try:
        materials_service.excluir_material(id_usuario, material)
        flash('Material excluido com sucesso.', 'success')
    
    except PermissionError:
        abort(403)
        return redirect(url_for('materials.detalhes_material', id=id))

    except Exception:
        flash('Não foi possível excluir o material', 'danger')
        return redirect(url_for('materials.detalhes_material', id=id))

    return redirect(url_for('user.perfil'))



@materials_bp.route('/detalhes/<int:id>')
@login_required
def detalhes_material(id):
    material = Material.query.get_or_404(id)
    try:
        materials_service.adicionar_visualizacao(id)

    except Exception as e:
        logging.error(f'Erro ao computar a vizualização da material{id}: {e}')
        db.session.rollback()
    return render_template('detalhes.html', material=material)