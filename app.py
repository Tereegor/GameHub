import base64
import logging
import os
import re
import sqlite3
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, flash, g, make_response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()
app.config["UPLOAD_FOLDER"] = "static/uploads"
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
DATABASE = "gamehub.db"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

if not os.path.exists(app.config["UPLOAD_FOLDER"]):
    os.makedirs(app.config["UPLOAD_FOLDER"])

CATEGORIES = {
    "accounts": {"en": "Accounts", "ru": "Аккаунты"},
    "items": {"en": "Items", "ru": "Предметы"},
    "services": {"en": "Services", "ru": "Услуги"},
    "other": {"en": "Other", "ru": "Другое"},
}


class User(UserMixin):
    def __init__(
            self, id, username, is_admin, is_super_admin, avatar=None, bio=None,
            balance=0.0, is_seller=False, seller_rating=0.0, email=None, phone_number=None):
        self.id = id
        self.username = username
        self.is_admin = is_admin
        self.is_super_admin = is_super_admin
        self.avatar = avatar or "default_avatar.png"
        self.bio = bio or ""
        self.balance = balance
        self.is_seller = is_seller
        self.seller_rating = seller_rating
        self.email = email
        self.phone_number = phone_number


@login_manager.user_loader
def load_user(user_id):
    try:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute(
                "SELECT id, username, is_admin, is_super_admin, avatar, bio, balance, "
                "is_seller, seller_rating, email, phone FROM users WHERE id = ?",
                (user_id,)
            )
            user_data = c.fetchone()
            if user_data:
                return User(
                    id=user_data[0],
                    username=user_data[1],
                    is_admin=bool(user_data[2]),
                    is_super_admin=bool(user_data[3]),
                    avatar=user_data[4],
                    bio=user_data[5],
                    balance=float(user_data[6]),
                    is_seller=bool(user_data[7]),
                    seller_rating=float(user_data[8]),
                    email=user_data[9],
                    phone_number=user_data[10],
                )
    except sqlite3.Error as e:
        logger.error(f"Error loading user {user_id}: {e}")
    return None


def init_db():
    try:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    is_admin INTEGER DEFAULT 0,
                    is_super_admin INTEGER DEFAULT 0,
                    avatar TEXT DEFAULT 'default_avatar.png',
                    bio TEXT DEFAULT '',
                    balance REAL DEFAULT 0.0,
                    is_seller INTEGER DEFAULT 0,
                    seller_rating REAL DEFAULT 0.0,
                    phone TEXT
                )""")
            c.execute("""
                CREATE TABLE IF NOT EXISTS listings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    price REAL NOT NULL,
                    category TEXT NOT NULL,
                    image TEXT,
                    sold INTEGER DEFAULT 0,
                    buyer_id INTEGER,
                    is_confirmed INTEGER DEFAULT 0,
                    confirmation_deadline TEXT,
                    timestamp TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (buyer_id) REFERENCES users(id)
                )""")
            c.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id INTEGER,
                    receiver_id INTEGER,
                    content TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (sender_id) REFERENCES users(id),
                    FOREIGN KEY (receiver_id) REFERENCES users(id)
                )""")
            c.execute("""
                CREATE TABLE IF NOT EXISTS reviews (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    listing_id INTEGER,
                    seller_id INTEGER,
                    buyer_id INTEGER,
                    rating INTEGER NOT NULL,
                    comment TEXT,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (listing_id) REFERENCES listings(id),
                    FOREIGN KEY (seller_id) REFERENCES users(id),
                    FOREIGN KEY (buyer_id) REFERENCES users(id)
                )""")
            c.execute("PRAGMA table_info(listings)")
            columns = [col[1] for col in c.fetchall()]
            for column, sql in [
                ("buyer_id", "ALTER TABLE listings ADD COLUMN buyer_id INTEGER"),
                ("is_confirmed", "ALTER TABLE listings ADD COLUMN is_confirmed INTEGER DEFAULT 0"),
                ("confirmation_deadline", "ALTER TABLE listings ADD COLUMN confirmation_deadline TEXT"),
                ("timestamp", "ALTER TABLE listings ADD COLUMN timestamp TEXT"),
            ]:
                if column not in columns:
                    c.execute(sql)
                    logger.info(f"Added column {column} to listings")
            c.execute("""
                CREATE TRIGGER IF NOT EXISTS ensure_buyer_id
                BEFORE UPDATE OF sold ON listings
                FOR EACH ROW
                WHEN NEW.sold = 1 AND NEW.buyer_id IS NULL
                BEGIN
                    SELECT RAISE(ABORT, 'buyer_id must be set when sold = 1');
                END;
            """)
            c.execute("UPDATE listings SET sold = 0 WHERE sold = 1 AND buyer_id IS NULL")
            c.execute("SELECT * FROM users WHERE username = 'superadmin'")
            if not c.fetchone():
                c.execute(
                    "INSERT INTO users (username, email, password_hash, is_super_admin, balance) "
                    "VALUES (?, ?, ?, ?, ?)",
                    ("superadmin", "superadmin@example.com", generate_password_hash("super123"), 1, 1000.0)
                )
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {e}")
        raise


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_phone_number(phone):
    digits = re.sub(r"\D", "", phone)
    return len(digits) == 11 and digits[0] in ("7", "8")


def is_valid_password(password):
    return len(password) >= 6 and re.search(r"[A-Za-z]", password) and re.search(r"[0-9]", password)


@app.before_request
def set_language():
    g.lang = "ru" if "lang-ru" in request.cookies.get("language", "") else "en"


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    try:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            if request.method == "POST":
                form_type = request.form.get("form_type")
                if form_type == "update_profile":
                    username = request.form.get("username", "").strip()
                    email = request.form.get("email", "").strip()
                    bio = request.form.get("bio", "")[:200]
                    password = request.form.get("password", "")
                    phone_number = request.form.get("phone_number", "").strip()
                    if not username or len(username) < 4:
                        flash("Username must be at least 4 characters.", "error")
                        return redirect(url_for("profile"))
                    if username != current_user.username:
                        c.execute("SELECT id FROM users WHERE username = ? AND id != ?", (username, current_user.id))
                        if c.fetchone():
                            flash("Username already taken.", "error")
                            return redirect(url_for("profile"))
                        c.execute("UPDATE users SET username = ? WHERE id = ?", (username, current_user.id))
                    if not email:
                        flash("Email is required.", "error")
                        return redirect(url_for("profile"))
                    if email != current_user.email:
                        c.execute("SELECT id FROM users WHERE email = ? AND id != ?", (email, current_user.id))
                        if c.fetchone():
                            flash("Email already taken.", "error")
                            return redirect(url_for("profile"))
                        c.execute("UPDATE users SET email = ? WHERE id = ?", (email, current_user.id))
                    c.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, current_user.id))
                    if password:
                        if not is_valid_password(password):
                            flash("Password must be 6+ chars with letters and numbers.", "error")
                            return redirect(url_for("profile"))
                        c.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                                  (generate_password_hash(password), current_user.id))
                    if phone_number:
                        if validate_phone_number(phone_number):
                            c.execute("UPDATE users SET phone = ?, is_seller = 1 WHERE id = ?",
                                      (phone_number, current_user.id))
                            flash("Phone added, seller status activated!", "success")
                        else:
                            flash("Invalid phone format. Use + and 10-15 digits.", "error")
                            return redirect(url_for("profile"))
                    if "avatar" in request.files:
                        file = request.files["avatar"]
                        if file and allowed_file(file.filename):
                            filename = secure_filename(f"{current_user.id}_{file.filename}")
                            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
                            c.execute("UPDATE users SET avatar = ? WHERE id = ?", (filename, current_user.id))
                            flash("Avatar updated!", "success")
                        else:
                            flash("Invalid file format.", "error")
                    conn.commit()
                    flash("Profile updated!", "success")
                elif form_type == "create_listing":
                    title = request.form.get("title", "").strip()
                    description = request.form.get("description", "").strip()
                    price = request.form.get("price", "0")
                    category = request.form.get("category", "")
                    if not title or not description or float(price) <= 0 or category not in CATEGORIES:
                        flash("Invalid listing data.", "error")
                    else:
                        image_data = None
                        if "listing_image" in request.files:
                            file = request.files["listing_image"]
                            if file and allowed_file(file.filename):
                                image_data = base64.b64encode(file.read()).decode("utf-8")
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
                        c.execute(
                            "INSERT INTO listings (user_id, title, description, price, category, image, timestamp) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (current_user.id, title, description, float(price), category, image_data, timestamp)
                        )
                        c.execute("UPDATE users SET is_seller = 1 WHERE id = ?", (current_user.id,))
                        conn.commit()
                        flash("Listing created!", "success")
                elif form_type == "deposit":
                    amount = float(request.form.get("amount", 0))
                    if amount > 0:
                        c.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, current_user.id))
                        conn.commit()
                        flash(f"Deposited ${amount:.2f}!", "success")
                    else:
                        flash("Amount must be positive.", "error")
                elif form_type == "leave_review":
                    listing_id = request.form.get("listing_id")
                    rating = int(request.form.get("rating"))
                    comment = request.form.get("comment", "").strip()
                    c.execute("SELECT user_id, buyer_id, is_confirmed FROM listings WHERE id = ?", (listing_id,))
                    listing = c.fetchone()
                    if not listing or listing[1] != current_user.id or not listing[2]:
                        flash("You cannot review this listing.", "error")
                    else:
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
                        c.execute(
                            "INSERT INTO reviews (listing_id, seller_id, buyer_id, rating, comment, timestamp) "
                            "VALUES (?, ?, ?, ?, ?, ?)",
                            (listing_id, listing[0], current_user.id, rating, comment, timestamp)
                        )
                        c.execute("SELECT AVG(rating) FROM reviews WHERE seller_id = ?", (listing[0],))
                        avg_rating = c.fetchone()[0] or 0.0
                        c.execute("UPDATE users SET seller_rating = ? WHERE id = ?", (avg_rating, listing[0]))
                        conn.commit()
                        flash("Review submitted!", "success")
            c.execute(
                "SELECT id, username, is_admin, is_super_admin, avatar, bio, balance, is_seller, "
                "seller_rating, email, phone FROM users WHERE id = ?",
                (current_user.id,)
            )
            user_data = c.fetchone()
            user = User(
                id=user_data[0],
                username=user_data[1],
                is_admin=bool(user_data[2]),
                is_super_admin=bool(user_data[3]),
                avatar=user_data[4],
                bio=user_data[5],
                balance=float(user_data[6]),
                is_seller=bool(user_data[7]),
                seller_rating=float(user_data[8]),
                email=user_data[9],
                phone_number=user_data[10]
            )
            c.execute(
                "SELECT id, title, description, price, category, image, sold, user_id, buyer_id, "
                "is_confirmed, confirmation_deadline, timestamp FROM listings WHERE user_id = ?",
                (current_user.id,)
            )
            listings = [
                {
                    "id": row[0],
                    "title": row[1],
                    "description": row[2],
                    "price": float(row[3]),
                    "category": CATEGORIES.get(row[4], {"en": "Unknown", "ru": "Неизвестно"})[g.lang],
                    "image": row[5],
                    "sold": bool(row[6]),
                    "user_id": row[7],
                    "buyer_id": row[8],
                    "is_confirmed": bool(row[9]),
                    "confirmation_deadline": row[10],
                    "timestamp": row[11]
                } for row in c.fetchall()
            ]
            c.execute(
                "SELECT id, title, description, price, category, image, sold, user_id, buyer_id, "
                "is_confirmed, confirmation_deadline, timestamp FROM listings WHERE buyer_id = ? AND sold = 1",
                (current_user.id,)
            )
            buyer_listings = [
                {
                    "id": row[0],
                    "title": row[1],
                    "description": row[2],
                    "price": float(row[3]),
                    "category": CATEGORIES.get(row[4], {"en": "Unknown", "ru": "Неизвестно"})[g.lang],
                    "image": row[5],
                    "sold": bool(row[6]),
                    "user_id": row[7],
                    "buyer_id": row[8],
                    "is_confirmed": bool(row[9]),
                    "confirmation_deadline": row[10],
                    "timestamp": row[11]
                } for row in c.fetchall()
            ]
            c.execute(
                "SELECT r.rating, r.comment, r.timestamp, u.username FROM reviews r "
                "JOIN users u ON r.buyer_id = u.id WHERE r.seller_id = ?",
                (current_user.id,)
            )
            reviews = [
                {
                    "rating": row[0],
                    "comment": row[1],
                    "timestamp": row[2],
                    "buyer_username": row[3]
                } for row in c.fetchall()
            ]
        return render_template(
            "profile.html", user=user, listings=listings, buyer_listings=buyer_listings,
            categories=CATEGORIES, reviews=reviews
        )
    except Exception as e:
        flash(f"Profile load error: {e}", "error")
        return render_template(
            "profile.html", user=current_user, listings=[], buyer_listings=[],
            categories=CATEGORIES, reviews=[]
        )


@app.route("/remove_phone", methods=["POST"])
@login_required
def remove_phone():
    try:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute("UPDATE users SET phone = NULL, is_seller = 0 WHERE id = ?", (current_user.id,))
            c.execute("DELETE FROM listings WHERE user_id = ? AND (sold = 0 OR (sold = 1 AND is_confirmed = 1))",
                      (current_user.id,))
            conn.commit()
            flash("Phone and seller status removed. Listings deleted.", "success")
    except Exception as e:
        flash(f"Error removing phone: {e}", "error")
    return redirect(url_for("profile"))


@app.route("/profile/<username>")
def user_profile(username):
    try:
        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute(
                "SELECT id, username, is_admin, is_super_admin, bio, seller_rating, avatar "
                "FROM users WHERE username = ?",
                (username,)
            )
            user = c.fetchone()
            if not user:
                flash("User not found.", "error")
                return redirect(url_for("index"))
            role = ("Супер-админ" if g.lang == "ru" else "Super Admin") if user["is_super_admin"] else \
                ("Админ" if g.lang == "ru" else "Admin") if user["is_admin"] else \
                    ("Продавец" if g.lang == "ru" else "Seller") if user["seller_rating"] > 0 else \
                        ("Пользователь" if g.lang == "ru" else "User")
            c.execute(
                "SELECT r.rating, r.comment, r.timestamp, u.username AS buyer_username "
                "FROM reviews r JOIN users u ON r.buyer_id = u.id WHERE r.seller_id = ? "
                "ORDER BY r.timestamp DESC",
                (user["id"],)
            )
            reviews = [
                {
                    "rating": row["rating"],
                    "comment": row["comment"],
                    "timestamp": row["timestamp"],
                    "buyer_username": row["buyer_username"]
                } for row in c.fetchall()
            ]
            c.execute(
                "SELECT id, title, description, price, category, image, timestamp, sold "
                "FROM listings WHERE user_id = ? ORDER BY timestamp DESC",
                (user["id"],)
            )
            listings = [
                {
                    "id": row["id"],
                    "title": row["title"],
                    "description": row["description"],
                    "price": float(row["price"]),
                    "category": CATEGORIES.get(row["category"], {"en": "Unknown", "ru": "Неизвестно"})[g.lang],
                    "image": row["image"],
                    "timestamp": row["timestamp"],
                    "sold": bool(row["sold"])
                } for row in c.fetchall()
            ]
            return render_template("user_profile.html", user=user, role=role, reviews=reviews, listings=listings)
    except Exception as e:
        flash(f"Error loading profile: {e}", "error")
        return redirect(url_for("index"))


@app.route("/")
def index():
    try:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute(
                "SELECT l.id, l.title, l.description, l.price, u.username, l.image, l.sold, l.category, l.timestamp "
                "FROM listings l JOIN users u ON l.user_id = u.id WHERE l.sold = 0 "
                "ORDER BY l.timestamp DESC LIMIT 5"
            )
            popular_listings = [
                {
                    "id": row[0],
                    "title": row[1],
                    "description": row[2],
                    "price": float(row[3]),
                    "seller": row[4],
                    "image": row[5],
                    "sold": bool(row[6]),
                    "category": CATEGORIES.get(row[7], {"en": "Unknown", "ru": "Неизвестно"})[g.lang],
                    "timestamp": row[8]
                } for row in c.fetchall()
            ]
        return render_template("index.html", popular_listings=popular_listings)
    except Exception as e:
        flash(f"Error loading listings: {e}", "error")
        return render_template("index.html", popular_listings=[])


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("profile"))
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        try:
            with sqlite3.connect(DATABASE) as conn:
                c = conn.cursor()
                c.execute(
                    "SELECT id, username, password_hash, is_admin, is_super_admin, avatar, bio, balance, "
                    "is_seller, seller_rating, email, phone FROM users WHERE username = ?",
                    (username,)
                )
                user_data = c.fetchone()
                if user_data and check_password_hash(user_data[2], password):
                    user = User(
                        id=user_data[0],
                        username=user_data[1],
                        is_admin=bool(user_data[3]),
                        is_super_admin=bool(user_data[4]),
                        avatar=user_data[5],
                        bio=user_data[6],
                        balance=float(user_data[7]),
                        is_seller=bool(user_data[8]),
                        seller_rating=float(user_data[9]),
                        email=user_data[10],
                        phone_number=user_data[11]
                    )
                    login_user(user, remember=True)
                    response = make_response(redirect(url_for("index")))
                    response.set_cookie("user_id", str(user.id), max_age=30 * 24 * 60 * 60, httponly=True, secure=True)
                    flash("Login successful!", "success")
                    return response
                flash("Invalid username or password.", "error")
        except Exception as e:
            flash(f"Login error: {e}", "error")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("profile"))
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        if len(username) < 4:
            flash("Username must be at least 4 characters.", "error")
            return render_template("register.html")
        if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
            flash("Please enter a valid email address.", "error")
            return render_template("register.html")
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("register.html")
        if not is_valid_password(password):
            flash("Password must be 6+ chars with letters and numbers.", "error")
            return render_template("register.html")
        try:
            with sqlite3.connect(DATABASE) as conn:
                c = conn.cursor()
                c.execute(
                    "INSERT INTO users (username, email, password_hash, balance) VALUES (?, ?, ?, ?)",
                    (username, email, generate_password_hash(password), 0.0)
                )
                conn.commit()
                flash("Registration successful! Please log in.", "success")
                return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username or email already taken.", "error")
    return render_template("register.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    response = make_response(redirect(url_for("index")))
    response.set_cookie("user_id", "", expires=0)
    flash("Logged out.", "success")
    return response


@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin():
    pass


@app.route("/marketplace")
def marketplace():
    pass


@app.route("/chats")
def chats():
    pass


@app.route("/faq")
def faq():
    return render_template("faq.html")


@app.before_request
def check_user_cookie():
    if not current_user.is_authenticated and "user_id" in request.cookies:
        user_id = request.cookies.get("user_id")
        user = load_user(user_id)
        if user:
            login_user(user, remember=True)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
