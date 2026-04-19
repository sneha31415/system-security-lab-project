from flask import Flask
from app_core.routes import register_routes
from app_core.database import init_db

app = Flask(__name__)
register_routes(app)
init_db()

if __name__ == "__main__":
    app.run(debug=True)