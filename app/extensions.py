from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()



from flask_login import LoginManager
login_manager = LoginManager()



from dotenv import load_dotenv
from supabase import create_client
from app.config import Config

load_dotenv()

supabase = create_client(Config.SUPABASE_URL, Config.SUPABASE_KEY)