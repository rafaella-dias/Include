import enum
    


class CorTag(enum.Enum):
    AZUL = 'azul'
    AMARELO = 'amarelo'
    VERDE = 'verde'
    ROSA = 'rosa'
    ROXO = 'roxo'



class Tipo(enum.Enum):
    ALUNO = 'aluno'
    SERVIDOR = 'servidor'
    ADMINISTRADOR = 'administrador'