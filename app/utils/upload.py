import os
from werkzeug.utils import secure_filename


#-----IMAGENS-----

ALLOWED_EXTENSIONS_IMAGES = {'png', 'jpg', 'jpeg', 'webp'}


def imagem_permitida(filename):
    return(
        '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS_IMAGES
    )


#-----ARQUIVOS-----

ALLOWED_EXTENSIONS_TO_MIME_TYPES = {
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


def validar_tipo(file):
    filename = secure_filename(file)

    if '.' not in filename:
        return False
    
    extensão = filename.rsplit('.', 1)[1].lower()
    mime = file.mimetype.split(';')[0]

    if extensão not in ALLOWED_EXTENSIONS_TO_MIME_TYPES:
        return False
    
    if mime not in ALLOWED_EXTENSIONS_TO_MIME_TYPES[extensão]:
        return False
    
    return True

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
    
    if not validar_tipo(file):
        return False, 'Tipo do arquivo inválido'
    
    tamanho = getfilesize(file)
    if tamanho > MAX_SIZE_ARQUIVOS:
        return False, 'O arquivo excede o tamanho permitido'
    
    return True, tamanho    