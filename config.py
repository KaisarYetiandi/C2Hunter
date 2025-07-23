import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    OUTPUT_DIR = os.getenv("OUTPUT_DIR", "reports")
    MAX_DOMAINS = int(os.getenv("MAX_DOMAINS", 100))
