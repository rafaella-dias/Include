from flask import Blueprint, request, render_template, redirect, url_for
from flask_login import login_required

from app.models import Curso, Atividade

main_bp = Blueprint("main", __name__)


@main_bp.route('/')
def inicio():
    return render_template('inicio.html')

@main_bp.route('/home')
def home():
    cursos = Curso.query.all()
    atividades = Atividade.query.order_by(Atividade.data_publicacao.desc()).all()
    return render_template('home.html', atividades=atividades, cursos=cursos)

@main_bp.route('/busca')
@login_required
def busca():
    termo = request.args.get('q', '').strip()

    if not termo:
        return redirect(url_for('main.home'))
    
    atividades = Atividade.query.filter(
        Atividade.titulo.ilike(f'%{termo}%')
    ).all()
    return render_template('busca.html', atividades=atividades, termo=termo)