from app.extensions import db
from app.models import Curso, Materia, Conteudo, Classe_Tag, Tag

def registrar_conteudo(nome, id_materia):
    conteudo_existente = Conteudo.query.filter_by(nome=nome, id_materia=id_materia).first()
    if conteudo_existente:
        raise ValueError('Esse conteúdo já foi registrado para esta matéria.')
    
    novo_conteudo = Conteudo(nome=nome, id_materia=id_materia)
    db.session.add(novo_conteudo)
    
    return None

