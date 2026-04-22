from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db
from app.models import Usuario



def buscar_usuario(email):
    return Usuario.query.filter_by(email=email).first()



def cadastrar_usuario(nome_completo, nome_usuario, email, senha):
    descricao = None
    tipo = 'usuario'
    public_id = None
    foto_url = None

    senha_hash = generate_password_hash(senha)

    try:
        novo_usuario = Usuario(
            nome_completo=nome_completo,
            nome_usuario=nome_usuario,
            email=email,
            descricao=descricao,
            senha=senha_hash,
            tipo=tipo,
            public_id=public_id,
            foto_url=foto_url
        )
        db.session.add(novo_usuario)
        db.session.commit()

        return novo_usuario

    except Exception as e: 
        db.session.rollback()
        print(e)
        raise 



def verif_corresp_senha(usuario, senha):
    if not usuario or not check_password_hash(usuario.senha, senha):
        return False
