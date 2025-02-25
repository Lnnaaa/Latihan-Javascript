from flask import Flask, request, render_template, redirect, session, url_for
import pandas as pd
import os
import hashlib

app = Flask(__name__, template_folder="login-sistem/templates", static_folder="login-sistem/static")
app.secret_key = "secret_key"

# Direktori penyimpanan file CSV
DATA_DIR = "login-sistem/data"

USERS_FILE = os.path.join(DATA_DIR, "users.csv")
ADMIN_FILE = os.path.join(DATA_DIR, "admin.csv")

# Pastikan folder data ada
os.makedirs(DATA_DIR, exist_ok=True)

# Pastikan file users.csv ada
if not os.path.exists(USERS_FILE):
    pd.DataFrame(columns=["username", "ip", "uuid"]).to_csv(USERS_FILE, index=False)

# Pastikan file admin.csv ada dan berisi admin default
if not os.path.exists(ADMIN_FILE):
    admin_data = pd.DataFrame([
        {"username": "Admin", "password": "admin123"},
        {"username": "Lana", "password": "lana123"}
    ])
    admin_data.to_csv(ADMIN_FILE, index=False)

def get_device_identifier():
    """Menghasilkan UUID atau uuid berdasarkan user-agent & IP."""
    user_agent = request.headers.get("User-Agent", "")
    ip = request.remote_addr

    # Hashing user-agent + IP sebagai pengganti uuid
    identifier = hashlib.sha256(f"{user_agent}{ip}".encode()).hexdigest()
    return identifier

def save_user(username, ip, uuid):
    """Menyimpan username, IP, dan uuid jika belum ada kombinasi yang sama."""
    users = pd.read_csv(USERS_FILE)

    # Cek apakah kombinasi username, IP, dan uuid sudah ada
    existing_user = users[(users["username"] == username) & (users["ip"] == ip) & (users["uuid"] == uuid)]

    if existing_user.empty:  # Jika belum ada, simpan
        new_user = pd.DataFrame({"username": [username], "ip": [ip], "uuid": [uuid]})
        users = pd.concat([users, new_user], ignore_index=True)
        users.to_csv(USERS_FILE, index=False)

def verify_admin(username, password):
    """Memeriksa apakah username dan password cocok dengan daftar admin."""
    admins = pd.read_csv(ADMIN_FILE).dropna()
    for _, row in admins.iterrows():
        if row["username"] == username and row["password"] == password:
            return True
    return False

@app.route("/", methods=["GET", "POST"])
def home():
    ip = request.remote_addr  # Ambil IP pengguna
    uuid = get_device_identifier()  # Ambil uuid (UUID) perangkat

    # **Auto Login jika uuid + IP sudah terdaftar**
    users = pd.read_csv(USERS_FILE)
    existing_user = users[(users["ip"] == ip) & (users["uuid"] == uuid)]

    if not existing_user.empty:
        session["username"] = existing_user.iloc[0]["username"]
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form.get("password", "")

        admins = pd.read_csv(ADMIN_FILE)["username"].dropna().tolist()

        if username in admins:
            if password:  # Jika sudah ada password, lakukan verifikasi
                if verify_admin(username, password):
                    session["username"] = username
                    return redirect(url_for("dashboard"))
                else:
                    return render_template("index.html", username=username, is_admin=True, error=True)
            else:
                return render_template("index.html", username=username, is_admin=True)
        else:
            save_user(username, ip, uuid)  # Simpan username + IP + uuid
            session["username"] = username
            return redirect(url_for("dashboard"))

    return render_template("index.html", username=None, is_admin=False)

@app.route("/dashboard")
def dashboard():
    """Halaman dashboard setelah login."""
    if "username" not in session:
        return redirect(url_for("home"))
    
    username = session["username"]
    admins = pd.read_csv(ADMIN_FILE)["username"].dropna().tolist()
    is_admin = username in admins  # Cek apakah user adalah admin

    return render_template("dashboard.html", username=username, is_admin=is_admin)

@app.route("/logout")
def logout():
    """Keluar dari sesi login & hapus IP dari users.csv."""
    if "username" in session:
        username = session["username"]
        ip = request.remote_addr
        uuid = get_device_identifier()
        users = pd.read_csv(USERS_FILE)
        
        # Hapus uuid & IP pengguna dari database
        users = users[~((users["username"] == username) & (users["ip"] == ip) & (users["uuid"] == uuid))]
        users.to_csv(USERS_FILE, index=False)

    session.pop("username", None)
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True, port=5500)
