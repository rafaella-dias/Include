from app.extensions import db
from app.models import Atividade, Curso, Materia, Tag
from app.services import storage_service, file_service

from sqlalchemy.orm import selectinload



def gerar_cursos_dados():
    cursos = Curso.query.options(selectinload(Curso.materias).selectinload(Materia.conteudos)).all()
    cursos_dados = []

    for curso in cursos:
        curso_dict = {
            "id": curso.id_curso,
            "nome": curso.nome,
            "materias": []
            }
        
        for materia in curso.materias:
            materia_dict = {
                "id": materia.id_materia,
                "nome": materia.nome,
                "conteudos": []
                }    

            for conteudo in materia.conteudos:
                conteudo_dict = {
                    "id": conteudo.id_conteudo,
                    "nome": conteudo.nome
                    }

                materia_dict["conteudos"].append(conteudo_dict)

            curso_dict["materias"].append(materia_dict)

        cursos_dados.append(curso_dict)
         
    return cursos_dados



def criar_atividade(titulo, descricao, id_curso, id_materia, id_conteudo, ids_tags, id_usuario):
    nova_atividade = Atividade(titulo=titulo,
                               descricao=descricao, 
                               id_curso=id_curso, 
                               id_materia=id_materia,
                               id_conteudo=id_conteudo, 
                               id_usuario=id_usuario )
    db.session.add(nova_atividade)
    db.session.flush()

    for id_tag in ids_tags:
        tag = Tag.query.get(id_tag)
        nova_atividade.tags.append(tag)
    
    return nova_atividade



def publicar(titulo, descricao, id_curso, id_materia, id_conteudo, ids_tags, id_usuario, arquivos):
    try:
        uploads = []
        #---- serviços ----
        nova_atividade = criar_atividade(titulo, descricao, id_curso, id_materia, id_conteudo, ids_tags, id_usuario)
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
            storage_service.delete_arquivo(arquivo['storage_path'])
        raise 
    
    return None 



def excluir_atividade(id_usuario, atividade):
    if atividade.id_usuario != id_usuario:
        raise PermissionError()
    
    try:
        for arquivo in atividade.arquivos:
            storage_service.delete_arquivo(arquivo.storage_path)
        db.session.delete(atividade)
        db.session.commit()

    except Exception as e:
        db.session.rollback()
        print(e)
        raise



def adicionar_visualizacao(atividade_id):
    db.session.query(Atividade).filter_by(id_atividade=atividade_id).update({
        Atividade.visualizacoes: Atividade.visualizacoes + 1
    })
    db.session.commit()