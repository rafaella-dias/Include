import json

from flask import Blueprint, request, render_template, redirect, url_for, flash, abort
from flask_login import login_required, current_user

from app.models import Atividade, Curso, Classe_Tag
from app.services import activities_service

activities_bp = Blueprint('activities', __name__)



@activities_bp.route('/publicar', methods = ['GET', 'POST'])
@login_required
def publicar():
    cursos = Curso.query.all()
    classes = Classe_Tag.query.all()
    cursos_json = json.dumps(activities_service.gerar_cursos_dados(), ensure_ascii=False)

    if request.method == 'GET':
        return render_template('publicar.html', cursos=cursos, classes=classes, cursos_json=cursos_json, form_data={})
    
    try: #tira o elif pq só tem POST como segunda opção
        #---- dados ----
        titulo = request.form.get('tituloForm')
        descricao = request.form.get('descricaoForm')
        id_curso = request.form.get('cursoForm')
        id_materia = request.form.get('materiaForm')
        id_conteudo = request.form.get('conteudoForm')
        ids_tags = request.form.getlist('tagsForm')
        id_usuario = current_user.id_usuario
        arquivos = request.files.getlist('arquivosForm')

        activities_service.publicar(titulo, descricao, id_curso, id_materia, id_conteudo, ids_tags, id_usuario, arquivos)
        flash('Atividade publicada com sucesso.', 'success')
        return redirect(url_for('user.perfil'))

    except ValueError as e:
        flash(str(e), 'warning')
        print(e)
        return render_template('publicar.html', cursos=cursos, classes=classes, cursos_json=cursos_json, form_data=request.form)
    
    except Exception as e:
        flash('Erro interno no servidor', 'danger')
        print(e)
        return render_template('publicar.html', cursos=cursos, classes=classes, cursos_json=cursos_json, form_data=request.form)



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
        return redirect(url_for('activities.detalhes_atividade', id=id))

    except Exception:
        flash('Não foi possível excluir a atividade', 'danger')
        return redirect(url_for('activities.detalhes_atividade', id=id))

    return redirect(url_for('user.perfil'))



@activities_bp.route('/detalhes/<int:id>')
@login_required
def detalhes_atividade(id):
    atividade = Atividade.query.get_or_404(id)
    return render_template('detalhes.html', atividade=atividade)