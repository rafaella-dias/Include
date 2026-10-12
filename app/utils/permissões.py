from functools import wraps
from flask import abort
from flask_login import current_user


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        #usuários autenticados como administradores não poderão acessar a rota
        if (current_user.is_authenticated and current_user.tipo !=  'administrador'):
            abort(403)

        return view(*args, **kwargs)

    return wrapped



def servidor_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        print('Tipo do usuário:', current_user.tipo)
        if (current_user.is_authenticated and current_user.tipo not in ('servidor', 'administrador')):
            abort(403)

        return view(*args, **kwargs)

    return wrapped
