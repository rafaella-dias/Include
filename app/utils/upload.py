import os
from werkzeug.utils import secure_filename



def getfilesize(file):
    file.seek(0, os.SEEK_END)
    tamanho = file.tell()
    file.seek(0)
    return tamanho


#-----IMAGENS-----
ALLOWED_EXTENSIONS_TO_MIME_TYPES_IMAGES = {
    'jpg' : ['image/jpeg'],
    'jpeg' : ['image/jpeg'],
    'png' : ['image/png'],
    'webp' : ['image/webp']
    }

MAX_SIZE_IMAGES = 1024 * 1024 * 5


def validar_tipo_img(file):
    filename = secure_filename(file.filename)
    if '.' not in filename:
        return False
    
    extensão = filename.rsplit('.', 1)[1].lower()
    mime = file.mimetype.split(';')[0]

    if extensão not in ALLOWED_EXTENSIONS_TO_MIME_TYPES_IMAGES:
        return False
    
    if mime not in ALLOWED_EXTENSIONS_TO_MIME_TYPES_IMAGES[extensão]:
        return False
    return True

def validar_imagem(file):
    if not file:
        return False, 'Nenhum arquivo enviado'
    
    if file.filename ==  '':
        return False, 'Nome do arquivo inválido'
    
    if not validar_tipo_file(file):
        return False, 'Tipo do arquivo inválido'
    
    tamanho = getfilesize(file)
    if tamanho > MAX_SIZE_IMAGES:
        return False, 'O arquivo excede o tamanho permitido'
    
    return True, tamanho  



#-----ARQUIVOS-----
ALLOWED_EXTENSIONS_TO_MIME_TYPES_FILES = {
    'pdf' : ['application/pdf'],

    'doc' : ['application/msword'],
    'docx' : ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],

    'ppt' : ['application/vnd.ms-powerpoint'],
    'pptx' : ['application/vnd.openxmlformats-officedocument.presentationml.presentation'],

    'xls' : ['application/vnd.ms-excel'],
    'xlsx' :  ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],

    'txt' : ['text/plain'],

    'jpg' : ['image/jpeg'],
    'jpeg' : ['image/jpeg'],
    'png' : ['image/png']
    }

MAX_SIZE_ARQUIVOS = 1024 * 1024 * 10 #10mb


def validar_tipo_file(file):
    filename = secure_filename(file.filename)
    if '.' not in filename:
        return False
    
    extensão = filename.rsplit('.', 1)[1].lower()
    mime = file.mimetype.split(';')[0]

    if extensão not in ALLOWED_EXTENSIONS_TO_MIME_TYPES_FILES:
        return False
    
    if mime not in ALLOWED_EXTENSIONS_TO_MIME_TYPES_FILES[extensão]:
        return False
    return True

def validar_arquivo(file):
    if not file:
        return False, 'Nenhum arquivo enviado'
    
    if file.filename ==  '':
        return False, 'Nome do arquivo inválido'
    
    if not validar_tipo_file(file):
        return False, 'Tipo do arquivo inválido'
    
    tamanho = getfilesize(file)
    if tamanho > MAX_SIZE_ARQUIVOS:
        return False, 'O arquivo excede o tamanho permitido'
    
    return True, tamanho    