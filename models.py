from db import db
from flask_login import UserMixin


class Usuario(UserMixin, db.Model):
    __tablename__ = 'usuarios'

    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(50), nullable=False, unique=True)
    senha = db.Column(db.String())

    def __repr__(self):
        return f'<{self.nome}>'