from flask import Flask


def create_app() -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def hello():
        return "Hello, Zitadel Flask App!"

    return app
