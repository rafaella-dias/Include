from app.extensions import db
from app.models import Atividade, Materia, Tag
from app.services import storage_service, activities_service, file_service



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


def publicar(titulo, descricao, id_materia, ids_tags, id_usuario, arquivos):
    try:
        uploads = []
        #---- serviços ----
        nova_atividade = activities_service.criar_atividade(titulo, descricao, id_materia, ids_tags, id_usuario)
        id_atividade = nova_atividade.id_atividade
                
        if not arquivos:
            raise ValueError('Arquivo não enviado')
        
        for arquivo in arquivos:
            dados_arquivo = storage_service.upload_arquivo(arquivo)#salva na nuvem e responde o 
            uploads.append(dados_arquivo)
            file_service.registrar_arquivo(dados_arquivo, id_atividade)#cadastra no banco baseado nos dados fornecidos pelo serviço de nuvem
        
        db.session.commit()

    except Exception:
        db.session.rollback()
        for arquivo in uploads:
            storage_service.delete_cloudinary(arquivo['public_id'])
        raise 
    
    return None # futura (atual) função orquestradora



def excluir_atividade(id_usuario, atividade):
    if atividade.id_usuario != id_usuario:
        raise PermissionError()
    
    try:
        for arquivo in atividade.arquivos:
            arquivo_url = arquivo.arquivo_url
            storage_service.delete_arquivo(arquivo.arquivo_url)
        db.session.delete(atividade)
        db.session.commit()

    except Exception as e:
        db.session.rollback()
        print(e)
        raise