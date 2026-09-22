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
    return render_template('home.html', atividades=materiais, cursos=cursos)

@main_bp.route('/busca')
@login_required
def busca():
    termo = request.args.get('q', '').strip()

    if not termo:
        return redirect(url_for('main.home'))
    
    materiais = Material.query.filter(
        Material.titulo.ilike(f'%{termo}%')
    ).all()
    return render_template('busca.html', atividades=materiais, termo=termo)