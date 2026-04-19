from flask import render_template, request, session, redirect, url_for

from app_core.database import check_login, get_comments, add_comment


def register_routes(app):
    app.secret_key = "dev-secret-key-change-in-prod"

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html")

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = check_login(username, password)

        if user:
            session["user_id"] = user[0]
            session["username"] = user[1]
            return redirect(url_for("dashboard"))

        return render_template("login.html", error="Invalid credentials")

    @app.route("/dashboard")
    def dashboard():
        if "user_id" not in session:
            return redirect(url_for("login"))
        return render_template("dashboard.html", username=session.get("username"))

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))

    @app.route("/comments", methods=["GET", "POST"])
    def comments():
        if request.method == "POST":
            username = request.form.get("username", "")
            content = request.form.get("content", "")
            add_comment(username, content)
            return redirect(url_for("comments"))

        all_comments = get_comments()
        return render_template("comments.html", comments=all_comments)