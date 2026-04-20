from app.extensions import db
from app.models import Atividade, Materia, Tag
from app.services import storage_service



def criar_atividade(titulo, descricao, id_materia, ids_tags, id_usuario):
    materia = Materia.query.get_or_404(id_materia)
    id_curso = materia.id_curso

    nova_atividade = Atividade(titulo=titulo,
                               descricao=descricao, 
                               id_curso=id_curso, 
                               id_materia=id_materia, 
                               id_usuario=id_usuario )
    db.session.add(nova_atividade)
    db.session.flush()

    for id_tag in ids_tags:
        tag = Tag.query.get(id_tag)
        nova_atividade.tags.append(tag)
    
    return nova_atividade



def publicar():
    return None # futura função orquestradora



def excluir_atividade(id_usuario, atividade):
    if atividade.id_usuario != id_usuario:
        raise PermissionError()
    
    try:
        for arquivo in atividade.arquivos:
            public_id = arquivo.public_id
            storage_service.delete_cloudinary(public_id)
        db.session.delete(atividade)
        db.session.commit()

    except Exception as e:
        db.session.rollback()
        print(e)
        raise