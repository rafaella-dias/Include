#Uma extensão é uma biblioteca que pode adicionar funcionalidades ao flask, podendo ser iniciadas depois no app.    
from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()



from flask_login import LoginManager
login_manager = LoginManager()



from flask_migrate import Migrate
migrate = Migrate()
#Flask-Migrate funciona como um atualizador do banco de dados automático, através do terminal, quase como um github, 
# fazendo uma tradução dos models para o banco de dados apenas um  "flask db migrate -m 'mensagem'", "flask db upgrade"



from dotenv import load_dotenv
from supabase import create_client
from app.config import Config

load_dotenv()

supabase = create_client(Config.SUPABASE_URL, Config.SUPABASE_KEY)
