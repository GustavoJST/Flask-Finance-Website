import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, lookup, usd
from re import search

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    purchased_stocks = db.execute(
        "SELECT symbol, num_shares FROM owned_stocks WHERE user_id = ? GROUP BY symbol", session["user_id"])
    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    symbols_info = []
    stocks_price_total = 0

    for symbol in purchased_stocks:
        api_results = lookup(symbol["symbol"])
        symbol_price_total = api_results["price"] * symbol["num_shares"]
        api_results["total_price"] = symbol_price_total
        api_results["num_shares"] = symbol["num_shares"]
        stocks_price_total += symbol_price_total
        symbols_info.append(api_results)

    total_cash = stocks_price_total + user_cash
    return render_template("index.html", purchased_stocks=purchased_stocks, total_cash=total_cash, user_cash=user_cash, symbols_info=symbols_info)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not symbol:
            return apology("Specify a stock symbol", 400)

        elif not shares:
            return apology("Specify a number of shares to buy", 400)

        elif not shares.isdigit() or int(shares) <= 0:
            return apology("Number of shares need to be a whole, positive number", 400)

        symbol = symbol.lower()
        shares = int(shares)
        symbol_price = lookup(symbol)
        if not symbol_price:
            return apology("Invalid stock symbol", 400)
        symbol_price = symbol_price["price"]

        total_price = shares * symbol_price
        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        remaining_user_cash = user_cash - total_price

        if remaining_user_cash < 0:
            return apology("Not enough money to buy the specified number of shares", 400)

        db.execute("INSERT INTO purchases (user_id, symbol, num_shares, share_price) VALUES (?, ?, ?, ?)",
                   session["user_id"], symbol, shares, symbol_price)
        db.execute("INSERT INTO owned_stocks (user_id, symbol, num_shares) VALUES (?, ?, ?)", session["user_id"], symbol, shares)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", remaining_user_cash, session["user_id"])

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute(
        "SELECT symbol, num_shares, share_price, date FROM purchases UNION ALL SELECT symbol, num_shares, share_price, date FROM sells WHERE user_id = ?",
        session["user_id"])
    for i in range(len(transactions)):
        transactions[i]["symbol"] = transactions[i]["symbol"].upper()

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        quote_result = lookup(symbol)

        if not symbol:
            return apology("Missing Symbol", 400)

        return render_template("quoted.html", quote_result=quote_result)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")

        if search("[~!*_+{}:;\'\"]", username):
            return apology("Invalid character in username", 400)

        query = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        if not username:
            return apology("Must provide username", 400)

        elif len(query) > 0:
            return apology("Username already exists", 400)

        elif not request.form.get("password") or not request.form.get("confirmation"):
            return apology("Password or/and Confirm Password can't be blank", 400)

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Password and Confirm Password don't match", 400)

        pwd_hash = generate_password_hash(request.form.get("password"))
        username = request.form.get("username")
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, pwd_hash)
        user_id = db.execute("SELECT id FROM users WHERE hash = ?", pwd_hash)
        session["user_id"] = user_id[0]["id"]
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        shares = request.form.get("shares")
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("Missing symbol", 400)

        elif not shares:
            return apology("Missing number of shares", 400)

        elif not shares.isdigit() or int(shares) <= 0:
            return apology("Number of shares need to be a whole, positive number", 400)

        symbol = symbol.lower()
        shares = int(shares)
        num_shares = db.execute("SELECT SUM(num_shares) FROM owned_stocks WHERE user_id = ? AND symbol = ?",
                                session["user_id"], symbol)[0]["SUM(num_shares)"]

        if not num_shares:
            return apology("You don't have shares of that stock", 400)

        elif (num_shares - shares) < 0:
            return apology("Trying to sell more shares than you have", 400)

        current_share_price = lookup(symbol)["price"]
        current_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        remaining_user_cash = current_cash + (current_share_price * shares)
        remaining_shares = num_shares - shares

        db.execute("DELETE FROM owned_stocks WHERE symbol = ? AND user_id = ?", symbol, session["user_id"])

        if remaining_shares > 0:
            db.execute("INSERT INTO owned_stocks (user_id, symbol, num_shares) VALUES (?, ?, ?)",
                       session["user_id"], symbol, remaining_shares)

        db.execute("UPDATE users SET cash = ? WHERE id = ?", remaining_user_cash, session["user_id"])
        db.execute("INSERT INTO sells (user_id, symbol, num_shares, share_price) VALUES (?, ?, ?, ?)",
                   session["user_id"], symbol, -abs(shares), current_share_price)
        return redirect("/")

    else:
        purchased_symbols = db.execute("SELECT symbol from owned_stocks WHERE user_id = ? GROUP BY symbol", session["user_id"])
        purchased_symbols = [symbol["symbol"].upper() for symbol in purchased_symbols]
        return render_template("sell.html", purchased_symbols=purchased_symbols)
