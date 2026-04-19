from flask import Flask
from app_core.routes import register_routes
from app_core.database import init_db
from waf.waf import WAFMiddleware
from config import WAF_ENABLED, DEBUG

app = Flask(__name__)
register_routes(app)
init_db()

if WAF_ENABLED:
    app.wsgi_app = WAFMiddleware(app.wsgi_app)
    print("[WAF] Middleware ACTIVE — requests will be inspected")
else:
    print("[WAF] Middleware DISABLED — app is vulnerable")


@app.route("/waf-status")
def waf_status():
    return {
        "waf_enabled": WAF_ENABLED,
        "status": "active" if WAF_ENABLED else "disabled",
    }

if __name__ == "__main__":
    app.run(debug=DEBUG, host="127.0.0.1", port=5000)