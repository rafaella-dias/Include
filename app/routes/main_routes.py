from flask import Blueprint, request, render_template, redirect, url_for
from flask_login import login_required

from app.models import Curso, Material

main_bp = Blueprint("main", __name__)


@main_bp.route('/')
def inicio():
    return render_template('inicio.html')

@main_bp.route('/home')
def home():
    cursos = Curso.query.all()
    materiais = Material.query.order_by(Material.data_publicacao.desc()).all()
    return render_template('home.html', materiais=materiais, cursos=cursos)

@main_bp.route('/busca')
@login_required
def busca():
    termo = request.args.get('q', '').strip()
    nome_curso = request.args.get('curso', '').strip()
    consulta = Material.query

    if termo:
        consulta = consulta.filter(Material.titulo.ilike(f'%{termo}%')).all()

    if nome_curso:
        consulta = consulta.filter(Material.curso.nome.ilike(f'%{nome_curso}')).all()

    materiais = consulta.order_by(Material.id_material.desc()).all()
    
    return render_template('busca.html', materiais=materiais, termo=termo, nome_curso=nome_curso)