from dotenv import load_dotenv
import os

load_dotenv()

class Config():
    SECRET_KEY = os.getenv("SENHA_SECRETA")

    SQLALCHEMY_DATABASE_URI = "sqlite:///DatabaseInclude.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    #CLOUDINARY_URL = os.getenv("CLOUDINARY_URL")

    SUPABASE_URL = os.getenv("SUPABASE_URL")
    SUPABASE_KEY = os.getenv("SUPABASE_KEY")
    SUPABASE_BUCKET = os.getenv("SUPABASE_BUCKET")