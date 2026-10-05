from app import create_app #importação simplficada da função
from app.extensions import db #importando a extensão centralizada!!

app = create_app()

app.run(debug=True) #modo de desenvolvimento