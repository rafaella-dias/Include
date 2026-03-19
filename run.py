from app import create_app #importação simplficada da função
from app.extensions import db #importando a extensão centralizada!!

app = create_app()

with app.app_context(): #isso é uma ferramenta do app para a criação de um "contexto" que indica que é uma aplicação flask, necessária para o sqlalchemy funcionar
    db.create_all() #criação das tabelas a partir dos models

app.run(debug=True) #modo de desenvolvimento