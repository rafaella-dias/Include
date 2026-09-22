from app.extensions import db
from app.enums import CorTag
from flask_login import UserMixin
from datetime import datetime, timezone



def agora_utc():
    return datetime.now(timezone.utc)
    


material_tag = db.Table('material_tag',
    db.Column('id_material', db.Integer, db.ForeignKey('materiais.id_material', ondelete='CASCADE'), primary_key=True),
    db.Column('id_tag', db.Integer, db.ForeignKey('tags.id_tag', ondelete='CASCADE'), primary_key=True)
)



class Usuario(UserMixin, db.Model):
    __tablename__ = 'usuarios'

    id_usuario = db.Column(db.Integer, primary_key=True)
    nome_completo = db.Column(db.String(50), nullable=False)
    nome_usuario = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(50), nullable=False, unique=True)
    descricao = db.Column(db.String(200))
    senha = db.Column(db.String(255), nullable=False)
    tipo =  db.Column(db.String(20), default='user', nullable=False)
    public_id = db.Column(db.String(100))
    foto_url = db.Column(db.String(255))

    materiais = db.relationship('Material', backref='autor', lazy=True)

    def get_id(self):
        return str(self.id_usuario)

    def __repr__(self):
        return f'<{self.nome_usuario}>'
    


class Material(db.Model):
    __tablename__ = 'materiais'

    id_material = db.Column(db.Integer, primary_key=True)

    titulo = db.Column(db.String(50), nullable=False)
    subtitulo = db.Column(db.String(100))
    descricao = db.Column(db.String(300), nullable=False)
    conteudo_textual = db.Column(db.Text)

    data_publicacao = db.Column(db.DateTime(timezone=True), default=agora_utc, nullable=False)
    visualizacoes = db.Column(db.Integer, default=0, nullable=False)
    downloads = db.Column(db.Integer, default=0, nullable=False)

    id_usuario = db.Column(db.Integer, db.ForeignKey('usuarios.id_usuario'), nullable=False)
    id_curso =  db.Column(db.Integer, db.ForeignKey('cursos.id_curso'), nullable=False)
    id_materia =  db.Column(db.Integer, db.ForeignKey('materias.id_materia'), nullable=False)
    id_conteudo = db.Column(db.Integer, db.ForeignKey('conteudos.id_conteudo'), nullable=True)#obs no True !!

    arquivos = db.relationship('Arquivo', backref='material', cascade='all, delete-orphan' , lazy=True)
    tags = db.relationship('Tag', secondary=material_tag, backref='materiais')

    def __repr__(self):
        return f'<{self.titulo}>'


   
class Arquivo(db.Model):
    __tablename__ = 'arquivos'

    id_arquivo = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    nome_unico = db.Column(db.String(300), nullable=False)
    tipo = db.Column(db.String(50), nullable=False)
    tamanho = db.Column(db.Integer, nullable=False)
    arquivo_url = db.Column(db.String(255), nullable=False)
    storage_path = db.Column(db.String(255), nullable=False)
    data_upload = db.Column(db.DateTime(timezone=True), default=agora_utc, nullable=False)
    id_material = db.Column(db.Integer, db.ForeignKey('materiais.id_material'), nullable=False)

    def __repr__(self):
        return f'<{self.nome}>'

    

class Curso(db.Model):
    __tablename__ = 'cursos'

    id_curso = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False, unique=True)

    materias = db.relationship('Materia', backref='curso', lazy=True, cascade='all, delete-orphan')
    materiais = db.relationship('Material', backref='curso', lazy=True)

    def __repr__(self):
        return f'<{self.nome}>'



class Materia(db.Model):
    __tablename__ = 'materias'

    id_materia = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False, unique=True)
    id_curso = db.Column(db.Integer, db.ForeignKey('cursos.id_curso'), nullable=False)
    
    conteudos = db.relationship('Conteudo', backref='materia', lazy=True, cascade='all, delete-orphan')
    materiais = db.relationship('Material', backref='materia', lazy=True)

    def __repr__(self):
        return f'<{self.nome}>'
    


class Conteudo(db.Model):
    __tablename__ = 'conteudos'

    __table_args__ = (db.UniqueConstraint('nome', 'id_materia', name='uq_conteudo_materia'),)

    id_conteudo = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(50), nullable=False)
    id_materia = db.Column(db.Integer, db.ForeignKey('materias.id_materia'), nullable=False)

    materiais = db.relationship('Material', backref='conteudo', lazy=True)

    def __repr__(self):
        return f'<{self.nome}>'



class Classe_Tag(db.Model):
    __tablename__ = 'classes_tag'

    id_classe = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(20), nullable=False, unique=True)
    cor = db.Column(db.Enum(CorTag), default=CorTag.AZUL, nullable=False)

    tags = db.relationship('Tag', backref='classe', lazy=True)

    def __repr__(self):
        return f'<{self.nome}>'




class Tag(db.Model):
    __tablename__ = 'tags'

    id_tag = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(20), nullable=False, unique=True)
    id_classe = db.Column(db.Integer, db.ForeignKey('classes_tag.id_classe'), nullable=False)

    def __repr__(self):
        return f'<{self.nome}>'
    


class Favorito(db.Model):
    __tablename__ = 'favoritos'

    __table_args__ = (db.UniqueConstraint('id_usuario', 'id_material', name='uq_usuario_material'),)

    id_favorito = db.Column(db.Integer, primary_key=True)
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuarios.id_usuario'), nullable=False)
    id_material = db.Column(db.Integer, db.ForeignKey('materiais.id_material'), nullable=False)
    data_favoritado = db.Column(db.DateTime(timezone=True), default=agora_utc, nullable=False)

    usuario = db.relationship('Usuario', backref='favoritos')
    material = db.relationship('Material', backref='favoritos')

    def __repr__(self):
        return f'<Favorito {self.id_usuario} -> {self.id_material}>'