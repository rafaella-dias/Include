from flask import Flask

from app.config import Config #importação das configurações
from app.extensions import db, login_manager, migrate #importação dos objetos do banco de dados criado pelo sqlalchemy e do login manager
#A importação dos models para o manuseio do flask-migrate/Asemblic é feita de forma indireta através de cada blueprint

from app.routes.main_routes import main_bp
from app.routes.auth_routes import auth_bp
from app.routes.user_routes import user_bp
from app.routes.materials_routes import materials_bp
from app.routes.admin_routes import admin_bp

import cloudinary

def create_app(): #implementando o Application Factory
    app = Flask(__name__)

    app.config.from_object(Config) #carregamento das configurações da classe Config

    db.init_app(app) #passando o app como argumento à criação do banco sqlalch.
    migrate.init_app(app, db)
    login_manager.init_app(app) #passando o app como argumento à criação do login manager

    login_manager.login_view = 'auth.login'

    @login_manager.user_loader
    def user_loader(id):
        from app.models import Usuario
        return Usuario.query.get(int(id))

    cloudinary.config(secure=True)

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(materials_bp)
    app.register_blueprint(admin_bp)

    @app.cli.command('criar-admin')
    def criar_admin():
        import click
        from getpass import getpass
        from werkzeug.security import generate_password_hash
        from app.models import Usuario
        from app.extensions import db

        click.echo('------Criar Administrador do Include------')
        nome_completo = click.prompt('Nome completo').strip()
        nome_usuario = click.prompt('Nome usuario').strip()
        email = click.prompt('E-mail').strip().lower()

        if not nome_completo or not nome_usuario or not email:
            click.echo('Erro: todos os campos são obrigatórios.')
            return

        if ' ' in nome_usuario:
            click.echo('Erro: o nome de usuário não pode conter espaços.')
            return

        existente = Usuario.query.filter(db.or_(Usuario.email == email, Usuario.nome_usuario == nome_usuario)).first()
        if existente:
            click.echo(
                'Erro: já existe uma conta com esse e-mail '
                'ou nome de usuário.'
            )
            return

        senha = getpass('Senha: ')
        confirmacao = getpass('Confirme a senha: ')

        if len(senha) < 8 or any(c.isspace() for c in senha):
            click.echo(
                'Erro: a senha precisa ter pelo menos 8 caracteres '
                'e não pode conter espaços.'
            )
            return

        if senha != confirmacao:
            click.echo('Erro: as senhas não correspondem.')
            return

        if not click.confirm(
            f'Criar administrador para {nome_usuario} ({email})?'
        ):
            click.echo('Operação cancelada.')
            return

        novo_admin = Usuario(
            nome_completo=nome_completo,
            nome_usuario=nome_usuario,
            email=email,
            senha=generate_password_hash(senha),
            tipo ='administrador',
            descricao=None,
            foto_url=None,
            id_cargo=None,
            especializacao=None,
            lattes_url=None,
        )

        try:
            db.session.add(novo_admin)
            db.session.commit()
            click.echo('Administrador criado com sucesso!')

        except:
            db.session.rollback()
            click.echo('Erro ao criar um novo Administrador. Nenhuma alteração foi confirmada.')
            raise click.ClickException('Verifique o erro no terminal e a configuração do banco.')

    return (app) #retorno da criação efetiva do app