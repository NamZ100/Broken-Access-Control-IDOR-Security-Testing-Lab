
from flask import Flask, request, session, redirect, url_for
import sqlite3
from pathlib import Path

app = Flask(__name__)
app.secret_key = "local-demo-secret"

DB = Path(__file__).with_name("idor.db")


def init_db():
    with sqlite3.connect(DB) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS invoices (
                id INTEGER PRIMARY KEY,
                owner TEXT NOT NULL,
                description TEXT NOT NULL
            )
        """)

        count = con.execute(
            "SELECT COUNT(*) FROM invoices"
        ).fetchone()[0]

        if count == 0:
            con.executemany(
                "INSERT INTO invoices VALUES (?, ?, ?)",
                [
                    (1, "alice", "Alice's demo invoice"),
                    (2, "bob", "Bob's demo invoice")
                ]
            )


def get_invoice(invoice_id):
    with sqlite3.connect(DB) as con:
        con.row_factory = sqlite3.Row
        return con.execute(
            "SELECT * FROM invoices WHERE id = ?",
            (invoice_id,)
        ).fetchone()


@app.route("/")
def home():
    if "user" not in session:
        return """
        <h2>IDOR Security Lab</h2>
        <a href='/login/alice'>Login as Alice</a><br>
        <a href='/login/bob'>Login as Bob</a>
        """

    user = session["user"]

    return f"""
    <h2>Welcome {user}</h2>
    <p>Your demo account is active.</p>
    <a href='/vulnerable/invoice/1'>Vulnerable endpoint</a><br>
    <a href='/secure/invoice/1'>Secure endpoint</a><br>
    <a href='/logout'>Logout</a>
    """


@app.route("/login/<username>")
def login(username):
    if username not in ["alice", "bob"]:
        return "Invalid user", 400

    session["user"] = username
    return redirect(url_for("home"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/vulnerable/invoice/<int:invoice_id>")
def vulnerable(invoice_id):
    if "user" not in session:
        return "Please login first", 401

    invoice = get_invoice(invoice_id)

    if invoice is None:
        return "Invoice not found", 404

    return f"""
    <h2>Vulnerable Invoice Page</h2>
    <p>Logged in as: {session['user']}</p>
    <p>Invoice ID: {invoice['id']}</p>
    <p>Owner: {invoice['owner']}</p>
    <p>Description: {invoice['description']}</p>
    """


@app.route("/secure/invoice/<int:invoice_id>")
def secure(invoice_id):
    if "user" not in session:
        return "Please login first", 401

    with sqlite3.connect(DB) as con:
        con.row_factory = sqlite3.Row

        invoice = con.execute(
            "SELECT * FROM invoices WHERE id = ? AND owner = ?",
            (invoice_id, session["user"])
        ).fetchone()

    if invoice is None:
        return "403 Forbidden: You cannot access this invoice", 403

    return f"""
    <h2>Secure Invoice Page</h2>
    <p>Logged in as: {session['user']}</p>
    <p>Invoice ID: {invoice['id']}</p>
    <p>Owner: {invoice['owner']}</p>
    <p>Description: {invoice['description']}</p>
    """


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
