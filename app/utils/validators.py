import re

regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
def validar_email(email):
    if not email:
        return False
    return bool(re.match(regex, email))



def validar_usuario(nome_usuario):
    if not nome_usuario:
        return False
    return ' ' not in nome_usuario



def validar_senha(senha):
    return len(senha) >= 8 or ' ' not in senha



def validar_confirm_senha(senha, confirmacao_senha):
    return senha == confirmacao_senha