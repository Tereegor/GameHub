import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, g
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()
app.config["UPLOAD_FOLDER"] = "static/uploads"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

if not os.path.exists(app.config["UPLOAD_FOLDER"]):
    os.makedirs(app.config["UPLOAD_FOLDER"])

# Категории для объявлений
CATEGORIES = {
    "items": {"en": "In-Game Items", "ru": "Игровые предметы"},
    "boosting": {"en": "Boosting Services", "ru": "Услуги бустинга"},
    "codes": {"en": "Digital Codes", "ru": "Цифровые коды"}
}


class User(UserMixin):
    def __init__(self, id, username, is_admin, is_super_admin, avatar=None, bio=None, balance=0.0, is_seller=False,
                 seller_rating=0):
        self.id = id
        self.username = username
        self.is_admin = is_admin
        self.is_super_admin = is_super_admin
        self.avatar = avatar
        self.bio = bio
        self.balance = balance
        self.is_seller = is_seller
        self.seller_rating = seller_rating


@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect("gamehub.db") as conn:
        c = conn.cursor()
        c.execute(
            "SELECT id, username, is_admin, is_super_admin, avatar, bio, balance, is_seller, seller_rating FROM users WHERE id = ?",
            (user_id,))
        user_data = c.fetchone()
        if user_data:
            return User(*user_data)
    return None


def init_db():
    with sqlite3.connect("gamehub.db") as conn:
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            is_super_admin INTEGER DEFAULT 0,
            avatar TEXT DEFAULT "default_avatar.png",
            bio TEXT,
            balance REAL DEFAULT 0.0,
            is_seller INTEGER DEFAULT 0,
            seller_rating INTEGER DEFAULT 0
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS listings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            price REAL NOT NULL,
            category TEXT NOT NULL,
            image TEXT,
            sold INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER,
            receiver_id INTEGER,
            content TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        )""")
        c.execute(
            "INSERT OR IGNORE INTO users (username, email, password_hash, is_super_admin, balance) VALUES (?, ?, ?, ?, ?)",
            ("superadmin", "superadmin@example.com", generate_password_hash("super123"), 1, 1000.0))
        conn.commit()


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.before_request
def set_language():
    g.lang = "ru" if "lang-ru" in request.cookies.get("language", "") else "en"


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    with sqlite3.connect("gamehub.db") as conn:
        c = conn.cursor()
        if request.method == "POST":
            form_type = request.form.get("form_type")
            if form_type == "update_profile":
                bio = request.form.get("bio", "")[:200]
                c.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, current_user.id))
                if "avatar" in request.files:
                    file = request.files["avatar"]
                    if file and allowed_file(file.filename):
                        filename = secure_filename(f"{current_user.id}_{file.filename}")
                        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
                        c.execute("UPDATE users SET avatar = ? WHERE id = ?", (filename, current_user.id))
                        flash("Аватар обновлен!" if g.lang == "ru" else "Avatar updated!", "success")
                    else:
                        flash("Недопустимый формат файла." if g.lang == "ru" else "Invalid file format.", "error")
                flash("Профиль обновлен!" if g.lang == "ru" else "Profile updated!", "success")
            elif form_type == "create_listing":
                title = request.form["title"].strip()
                description = request.form["description"].strip()
                price = float(request.form["price"])
                category = request.form["category"]
                if not title or not description or price <= 0 or category not in CATEGORIES:
                    flash("Неверные данные объявления." if g.lang == "ru" else "Invalid listing data.", "error")
                else:
                    image_filename = None
                    if "listing_image" in request.files:
                        file = request.files["listing_image"]
                        if file and allowed_file(file.filename):
                            image_filename = secure_filename(f"{current_user.id}_{file.filename}")
                            file.save(os.path.join(app.config["UPLOAD_FOLDER"], image_filename))
                    c.execute(
                        "INSERT INTO listings (user_id, title, description, price, category, image) VALUES (?, ?, ?, ?, ?, ?)",
                        (current_user.id, title, description, price, category, image_filename))
                    c.execute("UPDATE users SET is_seller = 1 WHERE id = ?", (current_user.id,))
                    flash("Объявление создано!" if g.lang == "ru" else "Listing created!", "success")
            elif form_type == "deposit":
                try:
                    amount = float(request.form["amount"])
                    if amount > 0:
                        c.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, current_user.id))
                        flash(f"Пополнено ${amount:.2f}!" if g.lang == "ru" else f"Deposited ${amount:.2f}!", "success")
                    else:
                        flash("Сумма должна быть положительной." if g.lang == "ru" else "Amount must be positive.",
                              "error")
                except ValueError:
                    flash("Неверная сумма." if g.lang == "ru" else "Invalid amount.", "error")
            conn.commit()

        c.execute("SELECT id, title, description, price, category, image, sold FROM listings WHERE user_id = ?",
                  (current_user.id,))
        listings = [{"id": row[0], "title": row[1], "description": row[2], "price": float(row[3]),
                     "category": CATEGORIES[row[4]][g.lang], "image": row[5], "sold": bool(row[6])} for row in
                    c.fetchall()]
    return render_template("profile.html", user=current_user, listings=listings, categories=CATEGORIES)


@app.route("/")
def index():
    with sqlite3.connect("gamehub.db") as conn:
        c = conn.cursor()
        c.execute(
            "SELECT l.id, l.title, l.description, l.price, u.username, l.image, l.sold, l.category FROM listings l JOIN users u ON l.user_id = u.id WHERE l.sold = 0 ORDER BY l.id DESC LIMIT 5")
        popular_listings = [
            {"id": row[0], "title": row[1], "description": row[2], "price": float(row[3]), "seller": row[4],
             "image": row[5], "sold": bool(row[6]), "category": CATEGORIES[row[7]][g.lang]} for row in c.fetchall()]
    return render_template("index.html", popular_listings=popular_listings)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("profile"))
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        with sqlite3.connect("gamehub.db") as conn:
            c = conn.cursor()
            c.execute(
                "SELECT id, username, password_hash, is_admin, is_super_admin, avatar, bio, balance, is_seller, seller_rating FROM users WHERE username = ?",
                (username,))
            user_data = c.fetchone()
            if user_data and check_password_hash(user_data[2], password):
                user = User(user_data[0], user_data[1], user_data[3], user_data[4], user_data[5], user_data[6],
                            user_data[7], user_data[8], user_data[9])
                login_user(user, remember=True)
                flash("Вход выполнен успешно!" if g.lang == "ru" else "Login successful!", "success")
                return redirect(url_for("index"))
            flash("Неверные данные." if g.lang == "ru" else "Invalid credentials.", "error")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("profile"))
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        if password != confirm_password:
            flash("Пароли не совпадают." if g.lang == "ru" else "Passwords do not match.", "error")
        else:
            try:
                with sqlite3.connect("gamehub.db") as conn:
                    c = conn.cursor()
                    c.execute("INSERT INTO users (username, email, password_hash, balance) VALUES (?, ?, ?, ?)",
                              (username, email, generate_password_hash(password), 0.0))
                    conn.commit()
                    flash("Регистрация успешна!" if g.lang == "ru" else "Registration successful!", "success")
                    return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Имя или email заняты." if g.lang == "ru" else "Username or email taken.", "error")
    return render_template("register.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Выход выполнен." if g.lang == "ru" else "Logged out.", "success")
    return redirect(url_for("index"))


@app.route("/faq")
def faq():
    return render_template("faq.html")


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
