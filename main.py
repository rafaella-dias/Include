#python
'''from functools import wraps'''
import re
import os

#Flask
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import LoginManager, login_user, login_required, logout_user, current_user

#Dados
from db import db
from models import Tag, Classe_Tag, Usuario

#Segurança
from werkzeug.security import generate_password_hash,check_password_hash

#.env
from dotenv import load_dotenv

#Cloudinary
import cloudinary
import cloudinary.uploader
import cloudinary.api



load_dotenv()



app = Flask(__name__)
app.secret_key = os.getenv('SENHA_SECRETA')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///DatabaseInclude.db'
db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

config = cloudinary.config(secure=True)

regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'


'''
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_autenthicaded or current_user.tipo != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

'''
ALLOWED_EXTENSIONS_IMAGES = {'png', 'jpeg', 'jpg', 'webp'}
def imagem_permitida(filename):
    return(
        '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS_IMAGES
    )


@login_manager.user_loader
def user_loader(id):
    usuario = db.session.get(Usuario, int(id))
    return usuario



@app.route('/')
def inicio():
    return render_template('inicio.html')


@app.route('/home')
@login_required
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    elif request.method == 'POST':
        email = request.form.get('emailForm')
        senha = request.form.get('senhaForm')

        if not re.match(regex, email):
            flash('E-mail inválido', 'danger')
            return render_template('login.html', form_data=request.form)
        
        usuario = Usuario.query.filter_by(email=email).first()

        if not usuario or not check_password_hash(usuario.senha, senha):
            flash('E-mail ou senha incorretos', 'danger')
            return render_template('login.html', form_data=request.form)
        
        login_user(usuario)
        return redirect(url_for('home'))


@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'GET':
        return render_template('cadastro.html')
    
    elif request.method == 'POST':
        nome_completo = request.form.get('nome_completoForm')
        nome_usuario = request.form.get('nome_usuarioForm')
        email = request.form.get('emailForm')
        senha = request.form.get('senhaForm')
        confirmacao_senha = request.form.get('confirmacao_senhaForm')

        if ' ' in nome_usuario:
            flash('O nome de usuário não deve ter espaços.')
            return render_template('cadastro.html', form_data=request.form)

        if not re.match(regex, email):
            flash('E-mail inválido', 'danger')
            return render_template('cadastro.html', form_data=request.form)

        if Usuario.query.filter_by(email=email).first():
            flash('E-mail já cadastrado', 'danger')
            return render_template('cadastro.html', form_data=request.form)
        
        if len(senha) < 8 or ' ' in senha:
            flash('A senha deve ter no mínimo 8 caracteres e não pode ter espaços', 'danger')
            return render_template('cadastro.html', form_data=request.form)

        if senha != confirmacao_senha:
            flash('As senhas devem ser iguais', 'danger')
            return render_template('cadastro.html', form_data=request.form)
        
        descricao = None
        tipo = 'usuario'
        public_id = None
        foto_url = None

        senha_hash = generate_password_hash(senha)

        novo_usuario = Usuario(nome_completo=nome_completo, 
                               nome_usuario=nome_usuario, 
                               email=email, 
                               descricao=descricao, 
                               senha=senha_hash, 
                               tipo=tipo, 
                               public_id=public_id, 
                               foto_url=foto_url)
        db.session.add(novo_usuario)
        db.session.commit()

        login_user(novo_usuario)

        return redirect(url_for('home'))


@app.route('/logout')
@login_required
def logout():  
    logout_user()
    return redirect(url_for('inicio'))


@app.route('/perfil')
@login_required
def perfil():
    return render_template('perfil.html')

    
@app.route('/perfil/editar', methods = ['GET', 'POST'])
@login_required
def editar_perfil():    
    if request.method == 'GET':
        return render_template('editar_perfil.html')
    
    elif request.method == 'POST':
        nome_completo = request.form.get('nome_completoForm')
        nome_usuario = request.form.get('nome_usuarioForm')
        descricao = request.form.get('descricaoForm')
        senha = request.form.get('senhaForm')
        confirmacao_senha = request.form.get('confirmacao_senhaForm')
        foto_perfil = request.files.get('foto_perfilForm')

        if nome_completo != current_user.nome_completo:
            current_user.nome_completo = nome_completo

        if nome_usuario != current_user.nome_usuario and not ' ' in nome_completo:
            current_user.nome_usuario = nome_usuario

        if descricao and descricao != current_user.descricao:
            current_user.descricao = descricao

        if senha:
            if len(senha) < 8 or ' ' in senha:
                flash('A senha deve ter no mínimo 8 caracteres e não pode ter espaços')
                return render_template('perfil.html')
            
            if senha != confirmacao_senha:
                flash('As senhas devem ser iguais')
                return render_template('perfil.html')
            
            current_user.senha = generate_password_hash(senha)

        if foto_perfil and foto_perfil.filename != '':
            if not imagem_permitida(foto_perfil.filename):
                flash('Formato de imagem inválido.', 'danger')
                return render_template('perfil.html')
            
            if not foto_perfil.mimetype.startswith('image/'):
                flash('O arquivo não é uma imagem válida', 'danger')
                return render_template('perfil.html')
            
            if current_user.public_id:
                cloudinary.uploader.destroy(current_user.public_id)

            response = cloudinary.uploader.upload(foto_perfil, 
                                                  folder = 'perfis', 
                                                  unique_filename=True, 
                                                  overwrite=True,
                                                  transformation = [{'width':  500, 'heigth': 500, 'crop': 'fill'}])
            foto_url = response.get('secure_url')
            public_id = response.get('public_id')

            current_user.foto_url = foto_url
            current_user.public_id = public_id

        db.session. commit()

        return redirect(url_for('perfil'))

    
@app.route('/delete', methods = ['POST'])
@login_required
def delete_image():
    try:
        cloudinary.uploader.destroy(current_user.public_id)
        current_user.public_id = None
        current_user.foto_url = None
        db.session.commit()
        
        flash('Foto de perfil removida com sucesso', 'success')

    except Exception:
        flash('Erro ao remover a imagem', 'danger')
    
    return redirect(url_for('perfil'))

@app.route('/publicar', methods = ['GET', 'POST'])
@login_required
def publicar():
    if request.method == 'GET':
        return render_template('publicar.html')
    
    elif request.methods == 'POST':
        titulo = (request.form.get('tituloForm'))
        descricao = request.form.get('descricaForm')



        arquivo = request.files.get('arquivoForm')

        nome = arquivo.filename
        tipo = arquivo.mimetype
        tamanho = len(arquivo.read())


@app.route('/tags', methods = ['GET', 'POST'])
@login_required
def gerenciar_tags():
    if request.method == 'GET': 
        all_classes = Classe_Tag.query.all()
        return render_template('tags.html', classes=all_classes)
    
    elif request.method == 'POST':
        nome = request.form.get('nomeForm')
        cor = request.form.get('corForm')
        categoria = request.form.ger('categoriaForm')

        tag_existente = Tag.queru.filter_by(nome=nome).first()
        if tag_existente:
            flash('Essa tag já foi registrada', 'danger')
            return render_template('tags.html')

        nova_tag = Tag(nome=nome, cor=cor, categoria=categoria)
        db.session.add(nova_tag)
        db.commit()



@app.route('/classes', methods = ['GET', 'POST'])
@login_required
def gerenciar_classes():
    if request.method == 'GET':
        return render_template('classe_tag.html')

    elif request.method =='POST':
        nome_classe = request.form.get('nome_classeForm')

        classe_existente = Classe_Tag.query.filter_by(nome=nome_classe).first()
        if classe_existente:
            flash('Essa classe já foi registrada', 'danger')
            return render_template('classe_tag.html', form_data=request.form)

        nova_classe = Classe_Tag(nome=nome_classe)
        db.session.add(nova_classe)
        db.session.commit()

        return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) #remover depois!!