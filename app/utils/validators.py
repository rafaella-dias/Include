import re



#---- autenticação e usuário----
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
    if not senha:
        return False
    return len(senha) >= 8 and ' ' not in senha



def validar_confirm_senha(senha, confirmacao_senha):
    if not confirmacao_senha:
        return False
    return senha == confirmacao_senha