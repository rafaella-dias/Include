from app.extensions import db
from app.models import Arquivo



def registrar_arquivo(dados_arquivo, id_atividade):
    novo_arquivo = Arquivo(nome=dados_arquivo['nome'], 
                            tipo=dados_arquivo['tipo'], 
                           tamanho=dados_arquivo['tamanho'], 
                           arquivo_url=dados_arquivo['secure_url'],
                           public_id=dados_arquivo['public_id'],
                           id_atividade=id_atividade)
    
    db.session.add(novo_arquivo)
    db.session.flush()

    return novo_arquivo