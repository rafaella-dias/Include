from flask import Flask

from app.config import Config #importação das configurações
from app.extensions import db, login_manager #importação dos objetos do banco de dados criado pelo sqlalchemy e do login manager

from app.routes.main_routes import main_bp
from app.routes.auth_routes import auth_bp
from app.routes.user_routes import user_bp
from app.routes.activities_routes import activities_bp
from app.routes.admin_routes import admin_bp

import cloudinary

def create_app(): #implementando o Application Factory
    app = Flask(__name__)

    app.config.from_object(Config) #carregamento das configurações da classe Config

    db.init_app(app) #passando o app como argumento à criação do banco sqlalch.
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
    app.register_blueprint(activities_bp)
    app.register_blueprint(admin_bp)

    return (app) #retorno da criação efetiva do app