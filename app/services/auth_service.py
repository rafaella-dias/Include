from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db
from app.utils import validators
from app.models import Usuario, Cargo



def buscar_usuario(email):
    return Usuario.query.filter_by(email=email).first()



def cadastrar_usuario(nome_completo, nome_usuario, email, senha, tipo, id_cargo=None, especializacao=None, lattes_url=None):
    if not validators.validar_tipo(tipo):
        raise ValueError('Tipo de usuário inválido')

    if tipo == 'aluno':
        id_cargo = None
        especializacao = None
        lattes_url = None

    elif tipo == 'servidor':
        if not id_cargo:
            raise ValueError('Selecione um cargo válido.')

        if not especializacao or not especializacao.strip():
            raise ValueError('Informe sua especialização.')

        if not validators.validar_lattes(lattes_url):
            raise ValueError('Informe um link válido do Currículo Lattes.')

        cargo = db.session.get(Cargo, id_cargo)

        if cargo is None:
            raise ValueError('Cargo inválido.')

    senha_hash = generate_password_hash(senha)

    try:
        novo_usuario = Usuario(
            nome_completo=nome_completo,
            nome_usuario=nome_usuario,
            email=email,
            descricao=None,
            senha=senha_hash,
            tipo=tipo,
            id_cargo=id_cargo,
            especializacao=especializacao,
            lattes_url=lattes_url,
            public_id=None,
            foto_url=None,
        )
        db.session.add(novo_usuario)
        db.session.commit()

        return novo_usuario

    except Exception as e: 
        db.session.rollback()
        print(e)
        raise 



def verif_corresp_senha(usuario, senha):
    if not usuario:
        return False
    return check_password_hash(usuario.senha, senha)
