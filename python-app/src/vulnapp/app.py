"""Application factory wiring the vulnerable blueprints together."""
from flask import Flask

from .config import Config
from .routes import auth, files, users


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    app.register_blueprint(users.bp)
    app.register_blueprint(files.bp)
    app.register_blueprint(auth.bp)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


if __name__ == "__main__":
    # CWE-489: debug server bound to all interfaces.
    create_app().run(host="0.0.0.0", port=5000, debug=True)
