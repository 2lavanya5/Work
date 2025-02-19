    
import os

class Config:
    SECRET_KEY = "e2715521df2ce63355f4e552185daf961e36be4ddb530004e8961c23a712765c"  # Generate using secrets.token_hex(32)
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = "sqlite:////Users/swarajdutta/Downloads/WEBAPP/database.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
