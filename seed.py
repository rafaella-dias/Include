from app import create_app
from app.extensions import db
from app.models import Curso, Materia, Classe_Tag, Tag



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

    classes_tag = {
        "Deficiências Físicas e Sensoriais": [
            "Deficiência Visual",
            "Deficiência Auditiva",
            "Deficiência Física",
            "Deficiência Intelectual",
            "Deficiência Múltipla"
        ],

        "Transtorno do Espectro Autista (TEA)": [
            "TEA"
        ],

        "Altas Habilidades / Superdotação": [
            "Superdotação"
        ],

        "Transtornos e Dificuldades Funcionais": [
            "Dislexia",
            "Discalculia",
            "Disgrafia",
            "Transtorno do Déficit de Atenção com Hiperatividade (TDAH)",
            "Transtorno do Processamento Auditivo Central (TPAC)"

        ]
    }


    for nome_curso, nomes_materias in cursos.items():
        curso = Curso.query.filter_by(nome=nome_curso).first()

        if not curso:
            curso = Curso(nome=nome_curso)

            db.session.add(curso)
            db.session.flush() #continuidade ao fluxo na sessão do sqlalchemy

        for nome_materia in nomes_materias:
            materia = Materia.query.filter_by(nome=nome_materia, id_curso=curso.id_curso).first()

            if not materia:
                materia = Materia(nome=nome_materia, id_curso=curso.id_curso)

                db.session.add(materia)

    for nome_classe, nomes_tags in classes_tag.items():
        classe = Classe_Tag.query.filter_by(nome=nome_classe).first()

        if not classe:
            classe = Classe_Tag(nome=nome_classe)

            db.session.add(classe)
            db.session.flush()

        for nome_tag in nomes_tags:
            tag = Tag.query.filter_by(nome=nome_tag, id_classe=classe.id_classe).first()

            if not tag:
                tag = Tag(nome=nome_tag, id_classe=classe.id_classe)

                db.session.add(tag)

    db.session.commit()
    print('Seed realizado com sucessso!')