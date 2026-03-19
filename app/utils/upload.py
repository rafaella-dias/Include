import os


#-----IMAGENS-----

ALLOWED_EXTENSIONS_IMAGES = {'png', 'jpeg', 'jpg', 'webp'}
def imagem_permitida(filename):
    return(
        '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS_IMAGES
    )


#-----ARQUIVOS-----

ALLOWED_EXTENSIONS_ARQUIVOS = {'png', 'jpg', 'jpeg', 'webp'}

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