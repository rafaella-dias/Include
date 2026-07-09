from app.extensions import db
from app.models import Arquivo



def registrar_arquivo(dados_arquivo, id_atividade):
    novo_arquivo = Arquivo(nome=dados_arquivo['nome'],
                           nome_unico=dados_arquivo['nome_unico'], 
                           tipo=dados_arquivo['tipo'], 
                           tamanho=dados_arquivo['tamanho'], 
                           arquivo_url=dados_arquivo['arquivo_url'],
                           storage_path=dados_arquivo['storage_path'],
                           id_atividade=id_atividade)
    
    db.session.add(novo_arquivo)
    db.session.flush()

    return novo_arquivo