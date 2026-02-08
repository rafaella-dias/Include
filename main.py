#python
'''from functools import wraps'''
import re
import os

#Flask
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import LoginManager, login_user, login_required, logout_user, current_user

#Dados
from db import db
from models import Arquivo, Atividade, Materia, Curso, Tag, Classe_Tag, Usuario

#Segurança
from werkzeug.security import generate_password_hash,check_password_hash
from werkzeug.utils import secure_filename

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


ALLOWED_EXTENSIONS_ARQUIVOS = {'png', 'jpg', 'jpeg'}

ALLOWED_MIME_TYPES_ARQUIVOS = {
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'text/plain',
    'image/jpeg',
    'image/png'}
MAX_SIZE_ARQUIVOS = 1024 * 1024 * 10

def extensão_permitida(filename):
    if '.' not in filename:
        return False
    extensão = filename.split('.', 1)[1].lower()
    return extensão in ALLOWED_EXTENSIONS_ARQUIVOS

def getfilesize(file):
    file.seek(0, os.SEEK_END)
    tamanho = file.tell()
    file.seek(0)
    return tamanho

def validar_arquivo(file):
    if not file:
        return False, 'Nenhum arquivo enviado'
    
    if file.filename ==  '':
        return False, 'Nome do arquivo inválido'
    
    if not extensão_permitida(file.filename):
        return False, 'Extensão do arquivo inválida'
    
    tamanho = getfilesize(file)
    if tamanho > MAX_SIZE_ARQUIVOS:
        return False, 'O arquivo excede o tamanho permitido'
    
    return True, tamanho


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
    atividades = Atividade.query.all()
    cursos = Curso.query.all()
    return render_template('home.html', atividades=atividades, cursos=cursos)


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
    atividades = Atividade.query.filter_by(id_usuario=current_user.id_usuario).order_by(Atividade.data_publicacao.desc()).all()
    return render_template('perfil.html', atividades=atividades)

    
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

        if nome_usuario != current_user.nome_usuario and not ' ' in nome_usuario:
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
                                                  transformation = [{'width':  500, 'height': 500, 'crop': 'fill'}])
            foto_url = response.get('secure_url')
            public_id = response.get('public_id')

            current_user.foto_url = foto_url
            current_user.public_id = public_id

        db.session. commit()

        flash('Dados editados com sucesso', 'success')
        return redirect(url_for('perfil'))

    
@app.route('/delete/image/perfil', methods = ['POST'])
@login_required
def delete_image():
    try:
        cloudinary.uploader.destroy(current_user.public_id)
        current_user.public_id = None
        current_user.foto_url = None
        db.session.commit()
        
        flash('Foto de perfil removida com sucesso', 'success')

    except Exception:
        flash('Não foi possível remover a imagem', 'danger')
    
    return redirect(url_for('perfil'))


@app.route('/delete/atividade/<int:id>', methods = ['POST'])
@login_required
def excluir_atividade(id):
    atividade = Atividade.query.get_or_404(id)

    if atividade.id_usuario != current_user.id_usuario:
        abort(403)

    try: 
        for arquivo in atividade.arquivos:
            cloudinary.uploader.destroy(arquivo.public_id)

        db.session.delete(atividade)
        db.session.commit()

        flash('Atividade excluida com sucesso', 'success')

    except Exception as e:
        db.session.rollback()
        flash('Não foi possível excluir a atividade', 'danger')

    return redirect(url_for('perfil'))


@app.route('/publicar', methods = ['GET', 'POST'])
@login_required
def publicar():
    materias = Materia.query.all()
    tags = Tag.query.all()

    if request.method == 'GET':
        return render_template('publicar.html', materias=materias, tags=tags)
    
    try: #tira o elif pq só tem POST como segunda opção
        titulo = request.form.get('tituloForm')
        descricao = request.form.get('descricaoForm')
        id_materia = request.form.get('materiaForm')
        ids_tags = request.form.getlist('tagsForm')
        materia = Materia.query.get_or_404(id_materia)
        id_curso = materia.id_curso

        nova_atividade = Atividade(titulo=titulo,
                                   descricao=descricao, 
                                   id_curso=id_curso, 
                                   id_materia=id_materia, 
                                   id_usuario=current_user.id_usuario )
        db.session.add(nova_atividade)
        db.session.flush()

        for id_tag in ids_tags:
            tag = Tag.query.get(id_tag)
            nova_atividade.tags.append(tag)

        arquivo = request.files.get('arquivoForm')
        
        valido, resultado = validar_arquivo(arquivo)

        if not valido:
            raise ValueError(resultado)

        nome = secure_filename(arquivo.filename)
        tipo = arquivo.mimetype 
        tamanho = resultado
        id_atividade = nova_atividade.id_atividade

        response = cloudinary.uploader.upload(arquivo,
                                              folder = 'atividades',
                                              unique_filename = True,
                                              overwrite = True,
                                              )
        
        secure_url = response.get('secure_url')
        public_id = response.get('public_id')
       
        novo_arquivo = Arquivo(nome=nome, 
                               tipo=tipo, 
                               tamanho=tamanho, 
                               arquivo_url=secure_url,
                               public_id=public_id,
                               id_atividade=id_atividade)

        db.session.add(novo_arquivo)
        db.session.commit()
        flash('Atividade publicada com sucesso.', 'success')
        return redirect(url_for('publicar'))

    except Exception as e:
        db.session.rollback()
        flash(str(e), 'danger')
        return redirect(url_for('publicar', form_data=request.form))



@app.route('/admin/materias', methods = ['GET', 'POST'])
@login_required
def gerenciar_materias():
    if request.method == 'GET': 
        all_cursos = Curso.query.all()
        return render_template('administrador/materias.html', cursos=all_cursos)
    
    elif request.method == 'POST':
        nome = request.form.get('nomeForm')
        id_curso = request.form.get('cursoForm')

        materia_existente = Materia.query.filter_by(nome=nome).first()
        if materia_existente:
            flash('Essa matéria já foi registrada', 'danger')
            return render_template('materias.html')

        nova_materia = Materia(nome=nome, id_curso=id_curso)
        db.session.add(nova_materia)
        db.session.commit()

        flash('Materia adicionada com sucesso!', 'success')
        return redirect(url_for('gerenciar_materias'))


@app.route('/admin/cursos', methods = ['GET', 'POST'])
@login_required
def gerenciar_cursos():
    if request.method == 'GET':
        return render_template('administrador/cursos.html')

    elif request.method =='POST':
        nome = request.form.get('nomeForm')

        curso_existente = Curso.query.filter_by(nome=nome).first()
        if curso_existente:
            flash('Esse curso já foi registrado', 'danger')
            return render_template('cursos.html', form_data=request.form)

        novo_curso = Curso(nome=nome)
        db.session.add(novo_curso)
        db.session.commit()

        flash('Curso adicionado com sucesso!', 'success')
        return redirect(url_for('gerenciar_cursos'))


@app.route('/admin/tags', methods = ['GET', 'POST'])
@login_required
def gerenciar_tags():
    if request.method == 'GET': 
        all_classes = Classe_Tag.query.all()
        return render_template('administrador/tags.html', classes=all_classes)
    
    elif request.method == 'POST':
        nome = request.form.get('nomeForm')
        cor = request.form.get('corForm')
        id_classe = request.form.get('classeForm')

        tag_existente = Tag.query.filter_by(nome=nome).first()
        if tag_existente:
            flash('Essa tag já foi registrada', 'danger')
            return redirect(url_for('tags.html'))

        nova_tag = Tag(nome=nome, cor=cor, id_classe=id_classe)
        db.session.add(nova_tag)
        db.session.commit()

        flash('Tag criada com sucesso!', 'success')
        return redirect(url_for('gerenciar_tags'))


@app.route('/admin/classes', methods = ['GET', 'POST'])
@login_required
def gerenciar_classes():
    if request.method == 'GET':
        return render_template('administrador/classe_tag.html')

    elif request.method =='POST':
        nome_classe = request.form.get('nome_classeForm')

        classe_existente = Classe_Tag.query.filter_by(nome=nome_classe).first()
        if classe_existente:
            flash('Essa classe já foi registrada', 'danger')
            return render_template('classe_tag.html', form_data=request.form)

        nova_classe = Classe_Tag(nome=nome_classe)
        db.session.add(nova_classe)
        db.session.commit()

        flash('Categoria criada com sucesso!', 'success')
        return redirect(url_for('gerenciar_classes'))
    

@app.route('/admin/dashboard')
@login_required
def dashboard():
    cursos = Curso.query.all()
    materias = Materia.query.all()
    classes = Classe_Tag.query.all()
    tags = Tag.query.all()
    
    return render_template('administrador/dashboard.html', cursos=cursos, materias=materias, classes=classes, tags=tags )



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) #remover depois!!