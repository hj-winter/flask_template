from flask import Flask


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'ASqVjo9xzF4sF7gG7EpJAhPQ1zBTIS'

    return app


