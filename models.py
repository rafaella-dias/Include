from db import db
from flask_login import UserMixin
from datetime import datetime


atividade_tag = db.Table('atividade_tag',
    db.Column('id_atividade', db.Integer, db.ForeignKey('atividades.id_atividade'), primary_key=True),
    db.Column('id_tag', db.Integer, db.ForeignKey('tags.id_tag'), primary_key=True)
)

class Usuario(UserMixin, db.Model):
    __tablename__ = 'usuarios'

    id_usuario = db.Column(db.Integer, primary_key=True)
    nome_completo = db.Column(db.String(50), nullable=False)
    nome_usuario = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(50), nullable=False, unique=True)
    descricao = db.Column(db.String(200))
    senha = db.Column(db.String(255), nullable=False)
    tipo =  db.Column(db.String(20), default='user')
    public_id = db.Column(db.String(100))
    foto_url = db.Column(db.String(255))

    atividades = db.relationship('Atividade', backref='autor', lazy=True)

    def get_id(self):
        return str(self.id_usuario)

    def __repr__(self):
        return f'<{self.nome_usuario}>'
    
class Atividade(db.Model):
    __tablename__ = 'atividades'

    id_atividade = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(50), nullable=False)
    descricao = db.Column(db.String(200))
    data_publicacao = db.Column(db.DateTime, default=datetime.utcnow)
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuarios.id_usuario'), nullable=False)
    id_curso =  db.Column(db.Integer, db.ForeignKey('cursos.id_curso'), nullable=False)
    id_materia =  db.Column(db.Integer, db.ForeignKey('materias.id_materia'), nullable=False)

    arquivos = db.relationship('Arquivo', backref='atividade', lazy=True)
    tags = db.relationship('Tag', secondary=atividade_tag, backref='atividades')

    def __repr__(self):
        return f'<{self.titulo}>'

   
class Arquivo(db.Model):
    __tablename__ = 'arquivos'

    id_arquivo = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    tipo = db.Column(db.String(50), nullable=False)
    tamanho = db.Column(db.Integer)
    arquivo_url = db.Column(db.String(255), nullable=False)
    data_upload = db.Column(db.DateTime, default=datetime.utcnow)
    id_atividade = db.Column(db.Integer, db.ForeignKey('atividades.id_atividade'), nullable=False)

    def __repr__(self):
        return f'<{self.nome}>'

    
class Curso(db.Model):
    __tablename__ = 'cursos'

    id_curso = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(50), nullable=False, unique=True)

    materias = db.relationship('Materia', backref='curso', lazy=True)
    atividades = db.relationship('Atividade', backref='curso', lazy=True)

    def __repr__(self):
        return f'<{self.nome}>'


class Materia(db.Model):
    __tablename__ = 'materias'

    id_materia = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(50), nullable=False, unique=True)
    id_curso = db.Column(db.Integer, db.ForeignKey('cursos.id_curso'))
    
    atividades = db.relationship('Atividade', backref='materia', lazy=True)

    def __repr__(self):
        return f'<{self.nome}>'

class Tag(db.Model):
    __tablename__ = 'tags'

    id_tag = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(20), nullable=False, unique=True)
    cor =  db.Column(db.String(20), nullable=False)
    id_classe = db.Column(db.Integer, db.ForeignKey('classes_tag.id_classe'), nullable=False)

    def __repr__(self):
        return f'<{self.nome}>'

class Classe_Tag(db.Model):
    __tablename__ = 'classes_tag'

    id_classe = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(20), nullable=False, unique=True)

    tags = db.relationship('Tag', backref='classe', lazy=True)

    def __repr__(self):
        return f'<{self.nome}>'