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



def validar_tipo(tipo):
    return tipo in ('aluno', 'servidor')



def validar_senha(senha):
    if not senha:
        return False
    return len(senha) >= 8 and ' ' not in senha



def validar_confirm_senha(senha, confirmacao_senha):
    if not confirmacao_senha:
        return False
    return senha == confirmacao_senha



from urllib.parse import urlsplit
def validar_lattes(url):
    if not url: 
        return False

    try:
        partes = urlsplit(url.strip())
        return(
            partes.scheme in ('http', 'https')
            and partes.hostname is not None
            and partes.hostname.lower() == 'lattes.cnpq.br'
            and bool(partes.path.strip('/'))
            and partes.username is None
            and partes.password is None
        )

    except ValueError:
        return False