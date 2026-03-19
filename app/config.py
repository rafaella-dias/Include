import os

class Config():
    SECRET_KEY = os.getenv("SENHA_SECRETA")

    SQLALCHEMY_DATABASE_URI = "sqlite:///DatabaseInclude.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    CLOUDINARY_URL = os.getenv("CLOUDINARY_URL")