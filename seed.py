from app import create_app
from app.extensions import db
from app.models import Curso, Materia



app = create_app()

with app.app_context():

    cursos = {
        "Informática": [
            "Programação para a Internet",
            "Banco de Dados",
            "Redes de Computadores",
            "Sistemas Operacionais",
            "Lógica de Programação"
        ],

        "Manutenção de Computadores": [
            "Arquitetura de Computadores",
            "Eletrônica",
            "Manutenção de Computadores",
            "Redes de Computadores em Sistemas Operacionais",
            "Sistemas Operacionais"
        ],

        "Química": [
            "Química Geral",
            "Química Orgânica",
            "Química Inorgânica",
            "Química Analítica",
            "Físico-Química"
        ],

        "Agropecuária": [
            "Agricultura",
            "Zootecnia",
            "Irrigação e Drenagem",
            "Solos",
            "Produção Vegetal"
        ]

    }


    for nome_curso, nomes_materias in cursos.items():
        curso = Curso.query.filter_by(nome=nome_curso).first()

        if not curso:
            curso = Curso(nome=nome_curso)

            db.session.add(curso)
            db.session.flush() #continuidade ao fluxo na sessão do sqlalchemy

        for nome_materia in nomes_materias:
            materia = Materia.query.filter_by(nome=nome_materia, id_curso=curso.id_curso)

            if not materia:
                materia = Materia(nome=nome_materia, id_curso=curso.id_curso).first()

                db.session.add(materia)

    db.session.commit()
    print('Seed realizado com sucessso!')