from flask import Flask, request

from admin import delete_user
from db import search_user
from files import read_file

app = Flask(__name__)


@app.route("/")
def index():
    return "Demo app is running"


@app.route("/search")
def search_api():
    name = request.args.get("name", "")
    return search_user(name)


@app.route("/file")
def file_api():
    path = request.args.get("path", "")
    return read_file(path)


@app.route("/admin/delete")
def admin_delete():
    uid = request.args.get("id", "")
    return delete_user(uid)


if __name__ == "__main__":
    app.run(debug=True)

