from flask import Blueprint, request, render_template, redirect, url_for, flash
from flask_login import login_required

from app.extensions import db
from app.models import Curso, Materia, Tag, Classe_Tag

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


@admin_bp.route('/materias', methods = ['GET', 'POST'])
@login_required
def gerenciar_materias():
    if request.method == 'GET': 
        all_cursos = Curso.query.all()
        return render_template('administrador/materias.html', cursos=all_cursos)
    
    elif request.method == 'POST':
        nome = request.form.get('nomeForm')
        id_curso = request.form.get('cursoForm')

        materia_existente = Materia.query.filter_by(nome=nome).first()
        if materia_existente:
            flash('Essa matéria já foi registrada', 'danger')
            return render_template('materias.html')

        nova_materia = Materia(nome=nome, id_curso=id_curso)
        db.session.add(nova_materia)
        db.session.commit()

        flash('Materia adicionada com sucesso!', 'success')
        return redirect(url_for('admin.gerenciar_materias'))


@admin_bp.route('/cursos', methods = ['GET', 'POST'])
@login_required
def gerenciar_cursos():
    if request.method == 'GET':
        return render_template('administrador/cursos.html')

    elif request.method =='POST':
        nome = request.form.get('nomeForm')

        curso_existente = Curso.query.filter_by(nome=nome).first()
        if curso_existente:
            flash('Esse curso já foi registrado', 'danger')
            return render_template('cursos.html', form_data=request.form)

        novo_curso = Curso(nome=nome)
        db.session.add(novo_curso)
        db.session.commit()

        flash('Curso adicionado com sucesso!', 'success')
        return redirect(url_for('admin.gerenciar_cursos'))


@admin_bp.route('/tags', methods = ['GET', 'POST'])
@login_required
def gerenciar_tags():
    if request.method == 'GET': 
        all_classes = Classe_Tag.query.all()
        return render_template('administrador/tags.html', classes=all_classes)
    
    elif request.method == 'POST':
        nome = request.form.get('nomeForm')
        cor = request.form.get('corForm')
        id_classe = request.form.get('classeForm')

        tag_existente = Tag.query.filter_by(nome=nome).first()
        if tag_existente:
            flash('Essa tag já foi registrada', 'danger')
            return redirect(url_for('tags.html'))

        nova_tag = Tag(nome=nome, cor=cor, id_classe=id_classe)
        db.session.add(nova_tag)
        db.session.commit()

        flash('Tag criada com sucesso!', 'success')
        return redirect(url_for('admin.gerenciar_tags'))


@admin_bp.route('/classes', methods = ['GET', 'POST'])
@login_required
def gerenciar_classes():
    if request.method == 'GET':
        return render_template('administrador/classe_tag.html')

    elif request.method =='POST':
        nome_classe = request.form.get('nome_classeForm')

        classe_existente = Classe_Tag.query.filter_by(nome=nome_classe).first()
        if classe_existente:
            flash('Essa classe já foi registrada', 'danger')
            return render_template('classe_tag.html', form_data=request.form)

        nova_classe = Classe_Tag(nome=nome_classe)
        db.session.add(nova_classe)
        db.session.commit()

        flash('Categoria criada com sucesso!', 'success')
        return redirect(url_for('admin.gerenciar_classes'))
    

@admin_bp.route('/dashboard')
@login_required
def dashboard():
    cursos = Curso.query.all()
    materias = Materia.query.all()
    classes = Classe_Tag.query.all()
    tags = Tag.query.all()
    
    return render_template('administrador/dashboard.html', cursos=cursos, materias=materias, classes=classes, tags=tags )
