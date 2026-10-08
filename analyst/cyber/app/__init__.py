from flask import Flask
try:
    from flask_socketio import SocketIO
except ImportError:
    SocketIO = None
from pathlib import Path
from dotenv import load_dotenv
import os

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")
    app.config["BASE_DIR"] = BASE_DIR
    app.config["EVE_PATH"] = BASE_DIR / "data" / "eve.json"
    app.config["DETECTION_MODE"] = os.getenv("DETECTION_MODE", "demo").lower()
    app.config["SURICATA_EVE_PATH"] = Path(os.getenv("SURICATA_EVE_PATH", str(BASE_DIR / "data" / "eve.json")))
    app.config["DB_PATH"] = BASE_DIR / "data" / "cyberanalyst.db"

    (BASE_DIR / "data").mkdir(exist_ok=True)

    from .routes import main
    app.register_blueprint(main)

    from .db import init_db
    init_db(app.config["DB_PATH"])

    from .services.event_processor import start_background_processor
    # Avoid duplicate collector threads under Flask's debug reloader.
    if not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        start_background_processor(app)

    return app


socketio = SocketIO(cors_allowed_origins='*') if SocketIO else None

def init_realtime(app):
    if socketio:
        socketio.init_app(app, cors_allowed_origins="*")
