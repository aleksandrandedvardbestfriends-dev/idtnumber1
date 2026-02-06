import os
import json
import time
import base64
import hashlib
import secrets
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, send_from_directory, session, redirect, url_for
from flask_cors import CORS
from functools import wraps
import uuid

app = Flask(__name__, template_folder='.', static_folder='static')
app.secret_key = secrets.token_hex(32)  # Секретный ключ для сессий
CORS(app)

# Папки для загрузки файлов
UPLOAD_FOLDER = 'uploads'
MEDIA_FOLDER = 'media'
LOGS_FOLDER = 'logs'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(MEDIA_FOLDER, exist_ok=True)
os.makedirs(LOGS_FOLDER, exist_ok=True)
os.makedirs(os.path.join(MEDIA_FOLDER, 'videos'), exist_ok=True)
os.makedirs(os.path.join(MEDIA_FOLDER, 'images'), exist_ok=True)
os.makedirs(os.path.join(MEDIA_FOLDER, 'stories'), exist_ok=True)
os.makedirs(os.path.join(MEDIA_FOLDER, 'avatars'), exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Конфигурация безопасности
MAX_REQUESTS_PER_MINUTE = 60  # Максимум запросов в минуту
MAX_COMMENTS_PER_HOUR = 20    # Максимум комментариев в час
MAX_POSTS_PER_DAY = 10        # Максимум постов в день
MIN_PASSWORD_LENGTH = 8       # Минимальная длина пароля

# JSON база данных
DB_FILE = 'database.json'
BANS_FILE = 'bans.json'
LOGS_FILE = os.path.join(LOGS_FOLDER, 'activity.log')

# Инициализация базы данных
def init_database():
    if not os.path.exists(DB_FILE):
        default_data = {
            "users": [],
            "posts": [],
            "videos": [],
            "clans": [
                {"id": "clan_1", "emoji": "😀", "name": "Улыбающиеся", "members": 150, "points": 12500},
                {"id": "clan_2", "emoji": "😂", "name": "Смеющиеся", "members": 120, "points": 9800},
                {"id": "clan_3", "emoji": "🥰", "name": "Влюбленные", "members": 95, "points": 7600},
                {"id": "clan_4", "emoji": "😎", "name": "Крутые", "members": 87, "points": 6500},
                {"id": "clan_5", "emoji": "🤔", "name": "Задумчивые", "members": 76, "points": 5400}
            ],
            "comments": [],
            "stories": [],
            "live_streams": [],
            "messages": [],
            "notifications": [],
            "reports": [],
            "admin_logs": [],
            "system_settings": {
                "maintenance": False,
                "registration_enabled": True,
                "max_file_size": 100,  # MB
                "spam_protection": True,
                "content_moderation": True
            }
        }
        save_database(default_data)
    
    # Инициализация бананов
    if not os.path.exists(BANS_FILE):
        with open(BANS_FILE, 'w') as f:
            json.dump({"ip_bans": [], "user_bans": [], "temp_bans": {}}, f)
    
    # Создаем первого администратора если нет пользователей
    db = load_database()
    if len(db["users"]) == 0:
        admin_user = {
            "id": "admin_001",
            "username": "admin",
            "displayName": "Администратор",
            "email": "admin@itd.social",
            "password": hash_password("admin123"),  # Сменить при первом входе!
            "emoji": "👑",
            "bio": "Главный администратор системы",
            "createdAt": datetime.now().isoformat(),
            "isAdmin": True,
            "isSuperAdmin": True,
            "isVerified": True,
            "notifications": 0,
            "clan": None,
            "followers": [],
            "following": [],
            "stats": {
                "posts": 0,
                "videos": 0,
                "stories": 0,
                "likes": 0
            },
            "settings": {
                "theme": "dark",
                "language": "ru",
                "notifications": True,
                "privacy": "public"
            },
            "permissions": {
                "manage_users": True,
                "manage_posts": True,
                "manage_comments": True,
                "view_logs": True,
                "ban_users": True,
                "system_settings": True
            },
            "last_login": None,
            "login_attempts": 0,
            "status": "active"
        }
        db["users"].append(admin_user)
        save_database(db)
        log_activity("SYSTEM", "system", "Created default admin account", "127.0.0.1")
    
    return db

def load_database():
    try:
        with open(DB_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return init_database()

def save_database(data):
    with open(DB_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def load_bans():
    try:
        with open(BANS_FILE, 'r') as f:
            return json.load(f)
    except:
        return {"ip_bans": [], "user_bans": [], "temp_bans": {}}

def save_bans(data):
    with open(BANS_FILE, 'w') as f:
        json.dump(data, f, indent=2)

# Хэширование пароля
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Логирование
def log_activity(user_id, action, details, ip=None):
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "user_id": user_id,
        "action": action,
        "details": details,
        "ip": ip or (request.remote_addr if hasattr(request, 'remote_addr') else "127.0.0.1")
    }
    
    # Запись в файл
    with open(LOGS_FILE, 'a', encoding='utf-8') as f:
        f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
    
    # Запись в базу данных
    db = load_database()
    db["admin_logs"].append(log_entry)
    if len(db["admin_logs"]) > 1000:  # Ограничиваем размер логов
        db["admin_logs"] = db["admin_logs"][-1000:]
    save_database(db)

# Защита от спама
class AntiSpam:
    def __init__(self):
        self.request_logs = {}
        self.comment_logs = {}
        self.post_logs = {}
    
    def check_rate_limit(self, ip_address, limit_type="requests"):
        now = time.time()
        
        if limit_type == "requests":
            logs = self.request_logs
            limit = MAX_REQUESTS_PER_MINUTE
            window = 60  # 1 минута
        elif limit_type == "comments":
            logs = self.comment_logs
            limit = MAX_COMMENTS_PER_HOUR
            window = 3600  # 1 час
        elif limit_type == "posts":
            logs = self.post_logs
            limit = MAX_POSTS_PER_DAY
            window = 86400  # 1 день
        else:
            return True
        
        if ip_address not in logs:
            logs[ip_address] = []
        
        # Удаляем старые записи
        logs[ip_address] = [t for t in logs[ip_address] if now - t < window]
        
        # Проверяем лимит
        if len(logs[ip_address]) >= limit:
            return False
        
        # Добавляем текущий запрос
        logs[ip_address].append(now)
        return True
    
    def check_content_spam(self, text, user_id=None):
        """Проверка текста на спам"""
        spam_keywords = [
            "купить", "продать", "заработок", "бинарные", "крипта",
            "казино", "ставки", "халява", "бесплатно", "реклама",
            "http://", "https://", "www.", ".ru", ".com",
            "прибыль", "инвестиции", "деньги", "быстро", "легко"
        ]
        
        text_lower = text.lower()
        
        # Проверка на ключевые слова
        spam_score = 0
        for keyword in spam_keywords:
            if keyword in text_lower:
                spam_score += 1
        
        # Проверка на слишком много ссылок
        link_count = text_lower.count('http://') + text_lower.count('https://') + text_lower.count('www.')
        if link_count > 2:
            spam_score += link_count
        
        # Проверка на повторяющиеся символы
        if '!!!!!' in text or '?????' in text or '......' in text:
            spam_score += 2
        
        return spam_score > 3  # Если больше 3 баллов - считаем спамом

anti_spam = AntiSpam()

# Проверка бана
def is_banned(ip_address=None, user_id=None):
    bans = load_bans()
    now = datetime.now().isoformat()
    
    # Проверка IP банов
    if ip_address:
        for ban in bans["ip_bans"]:
            if ban["ip"] == ip_address:
                if "expires" in ban and ban["expires"] < now:
                    # Удаляем просроченный бан
                    bans["ip_bans"] = [b for b in bans["ip_bans"] if b["ip"] != ip_address]
                    save_bans(bans)
                else:
                    return True, ban.get("reason", "IP заблокирован")
    
    # Проверка банов пользователей
    if user_id:
        if user_id in bans["user_bans"]:
            return True, "Аккаунт заблокирован"
        
        # Проверка временных банов
        if user_id in bans["temp_bans"]:
            ban_info = bans["temp_bans"][user_id]
            if ban_info["expires"] > now:
                return True, f"Временная блокировка до {ban_info['expires']}"
            else:
                # Удаляем просроченный бан
                del bans["temp_bans"][user_id]
                save_bans(bans)
    
    return False, None

# Декораторы для проверки
def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Проверка сессии администратора
        if 'admin_id' not in session:
            return jsonify({"error": "Требуется авторизация администратора"}), 401
        
        db = load_database()
        admin = find_user_by_id(session['admin_id'], db)
        
        if not admin or not admin.get('isAdmin'):
            return jsonify({"error": "Недостаточно прав"}), 403
        
        return f(*args, **kwargs, admin=admin)
    return decorated_function

def require_super_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return jsonify({"error": "Требуется авторизация"}), 401
        
        db = load_database()
        admin = find_user_by_id(session['admin_id'], db)
        
        if not admin or not admin.get('isSuperAdmin'):
            return jsonify({"error": "Требуются права супер-администратора"}), 403
        
        return f(*args, **kwargs, admin=admin)
    return decorated_function

def spam_protection(limit_type="requests"):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip_address = request.remote_addr
            
            # Проверка бана по IP
            banned, reason = is_banned(ip_address=ip_address)
            if banned:
                return jsonify({"error": f"Доступ заблокирован: {reason}"}), 403
            
            # Проверка лимита запросов
            if not anti_spam.check_rate_limit(ip_address, limit_type):
                log_activity("SYSTEM", "spam_block", f"Rate limit exceeded for IP: {ip_address}", ip_address)
                return jsonify({"error": "Слишком много запросов. Попробуйте позже."}), 429
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Вспомогательные функции
def generate_id(prefix):
    return f"{prefix}_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"

def find_user_by_id(user_id, db):
    for user in db["users"]:
        if user["id"] == user_id:
            return user
    return None

def find_user_by_username(username, db):
    for user in db["users"]:
        if user["username"] == username:
            return user
    return None

def find_post_by_id(post_id, db):
    for post in db["posts"]:
        if post["id"] == post_id:
            return post
    return None

def find_video_by_id(video_id, db):
    for video in db["videos"]:
        if video["id"] == video_id:
            return video
    return None

def find_clan_by_id(clan_id, db):
    for clan in db["clans"]:
        if clan["id"] == clan_id:
            return clan
    return None

# ==================== АДМИН ПАНЕЛЬ ====================

@app.route('/admin')
def admin_panel():
    """Главная страница админ панели"""
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    
    db = load_database()
    admin = find_user_by_id(session['admin_id'], db)
    
    if not admin or not admin.get('isAdmin'):
        return redirect(url_for('admin_login'))
    
    return render_template('admin_panel.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Страница входа для администраторов"""
    if request.method == 'GET':
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>ITD Admin - Login</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    margin: 0;
                }
                .login-box {
                    background: white;
                    padding: 2rem;
                    border-radius: 10px;
                    box-shadow: 0 10px 25px rgba(0,0,0,0.1);
                    width: 300px;
                }
                .login-box h1 {
                    color: #333;
                    text-align: center;
                    margin-bottom: 1.5rem;
                }
                .input-group {
                    margin-bottom: 1rem;
                }
                .input-group label {
                    display: block;
                    margin-bottom: 0.5rem;
                    color: #666;
                }
                .input-group input {
                    width: 100%;
                    padding: 0.75rem;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    font-size: 1rem;
                }
                .btn {
                    width: 100%;
                    padding: 0.75rem;
                    background: #667eea;
                    color: white;
                    border: none;
                    border-radius: 5px;
                    font-size: 1rem;
                    cursor: pointer;
                    transition: background 0.3s;
                }
                .btn:hover {
                    background: #5a67d8;
                }
                .error {
                    color: #e53e3e;
                    text-align: center;
                    margin-top: 1rem;
                }
            </style>
        </head>
        <body>
            <div class="login-box">
                <h1>🔐 ITD Admin</h1>
                <form method="POST">
                    <div class="input-group">
                        <label>Имя пользователя</label>
                        <input type="text" name="username" required>
                    </div>
                    <div class="input-group">
                        <label>Пароль</label>
                        <input type="password" name="password" required>
                    </div>
                    <button type="submit" class="btn">Войти</button>
                </form>
            </div>
        </body>
        </html>
        '''
    
    elif request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return redirect(url_for('admin_login'))
        
        db = load_database()
        user = None
        
        for u in db["users"]:
            if u["username"] == username and u.get('isAdmin'):
                user = u
                break
        
        if not user:
            log_activity("SYSTEM", "admin_login_failed", f"Invalid username: {username}", request.remote_addr)
            return redirect(url_for('admin_login'))
        
        # Проверка пароля
        if user['password'] != hash_password(password):
            # Счетчик попыток входа
            user['login_attempts'] = user.get('login_attempts', 0) + 1
            save_database(db)
            
            log_activity(user['id'], "admin_login_failed", "Invalid password", request.remote_addr)
            
            # Блокировка после 5 неудачных попыток
            if user['login_attempts'] >= 5:
                bans = load_bans()
                bans["user_bans"].append(user['id'])
                save_bans(bans)
                log_activity("SYSTEM", "admin_banned", f"Admin account locked: {user['id']}")
            
            return redirect(url_for('admin_login'))
        
        # Сброс счетчика попыток
        user['login_attempts'] = 0
        user['last_login'] = datetime.now().isoformat()
        save_database(db)
        
        # Создание сессии
        session['admin_id'] = user['id']
        session['admin_name'] = user['displayName']
        
        log_activity(user['id'], "admin_login_success", "Admin logged in", request.remote_addr)
        
        return redirect(url_for('admin_panel'))

@app.route('/admin/logout')
def admin_logout():
    """Выход из админ панели"""
    if 'admin_id' in session:
        log_activity(session['admin_id'], "admin_logout", "Admin logged out")
        session.pop('admin_id', None)
        session.pop('admin_name', None)
    return redirect(url_for('admin_login'))

# ==================== АДМИН API ====================

@app.route('/admin/api/dashboard')
@require_admin
def admin_dashboard(admin):
    """Получение статистики для дашборда"""
    db = load_database()
    bans = load_bans()
    
    # Статистика
    stats = {
        "total_users": len(db["users"]),
        "total_posts": len(db["posts"]),
        "total_videos": len(db["videos"]),
        "total_comments": len(db["comments"]),
        "active_stories": len([s for s in db["stories"] if 
                              datetime.fromisoformat(s["createdAt"]) > datetime.now() - timedelta(hours=24)]),
        "active_live": len([s for s in db["live_streams"] if s.get("active", False)]),
        "reports_pending": len([r for r in db["reports"] if r.get("status") == "pending"]),
        "banned_ips": len(bans["ip_bans"]),
        "banned_users": len(bans["user_bans"]),
        "temp_bans": len(bans["temp_bans"])
    }
    
    # Последние действия
    recent_activity = db["admin_logs"][-50:][::-1]  # Последние 50 записей
    
    # Новые пользователи (последние 7 дней)
    week_ago = (datetime.now() - timedelta(days=7)).isoformat()
    new_users = [u for u in db["users"] if u["createdAt"] > week_ago]
    
    # Популярный контент
    popular_posts = sorted(db["posts"], key=lambda x: len(x.get("likes", [])), reverse=True)[:10]
    popular_videos = sorted(db["videos"], key=lambda x: x.get("views", 0), reverse=True)[:10]
    
    return jsonify({
        "success": True,
        "stats": stats,
        "recent_activity": recent_activity[:20],
        "new_users": len(new_users),
        "popular_posts": popular_posts,
        "popular_videos": popular_videos,
        "system_settings": db.get("system_settings", {})
    })

@app.route('/admin/api/users', methods=['GET'])
@require_admin
def admin_get_users(admin):
    """Получение списка пользователей"""
    db = load_database()
    
    # Фильтры
    search = request.args.get('search', '')
    role = request.args.get('role', 'all')
    status = request.args.get('status', 'all')
    limit = int(request.args.get('limit', 50))
    page = int(request.args.get('page', 1))
    
    users = db["users"]
    
    # Применяем фильтры
    if search:
        search = search.lower()
        users = [u for u in users if search in u["username"].lower() or search in u["displayName"].lower()]
    
    if role != 'all':
        if role == 'admin':
            users = [u for u in users if u.get('isAdmin', False)]
        elif role == 'user':
            users = [u for u in users if not u.get('isAdmin', False)]
    
    if status != 'all':
        if status == 'verified':
            users = [u for u in users if u.get('isVerified', False)]
        elif status == 'unverified':
            users = [u for u in users if not u.get('isVerified', False)]
    
    # Пагинация
    total = len(users)
    start = (page - 1) * limit
    end = start + limit
    paginated_users = users[start:end]
    
    # Удаляем пароли
    for user in paginated_users:
        if 'password' in user:
            del user['password']
    
    return jsonify({
        "success": True,
        "users": paginated_users,
        "total": total,
        "page": page,
        "pages": (total + limit - 1) // limit
    })

@app.route('/admin/api/users/<user_id>', methods=['GET', 'PUT', 'DELETE'])
@require_admin
def admin_manage_user(admin, user_id):
    """Управление конкретным пользователем"""
    db = load_database()
    user = find_user_by_id(user_id, db)
    
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404
    
    if request.method == 'GET':
        # Получение информации о пользователе
        user_data = user.copy()
        if 'password' in user_data:
            del user_data['password']
        
        # Получаем активность пользователя
        user_activity = [log for log in db["admin_logs"] if log.get("user_id") == user_id][-20:]
        
        # Получаем контент пользователя
        user_posts = [p for p in db["posts"] if p["userId"] == user_id]
        user_videos = [v for v in db["videos"] if v["userId"] == user_id]
        
        return jsonify({
            "success": True,
            "user": user_data,
            "activity": user_activity,
            "posts_count": len(user_posts),
            "videos_count": len(user_videos),
            "followers_count": len(user.get("followers", [])),
            "following_count": len(user.get("following", []))
        })
    
    elif request.method == 'PUT':
        # Обновление пользователя
        data = request.json
        if not data:
            return jsonify({"error": "Нет данных"}), 400
        
        # Проверяем права (супер-админ может менять всё, обычный админ только некоторые поля)
        if not admin.get('isSuperAdmin'):
            allowed_fields = ['isVerified', 'bio', 'status']
            for field in data:
                if field not in allowed_fields:
                    return jsonify({"error": f"Недостаточно прав для изменения поля: {field}"}), 403
        
        # Обновляем поля
        for key, value in data.items():
            if key in ['isAdmin', 'isSuperAdmin', 'permissions'] and not admin.get('isSuperAdmin'):
                continue  # Пропускаем чувствительные поля
            
            if key == 'password' and value:
                user[key] = hash_password(value)
            elif key == 'status' and value == 'banned':
                # Бан пользователя
                bans = load_bans()
                if user_id not in bans["user_bans"]:
                    bans["user_bans"].append(user_id)
                    save_bans(bans)
                    log_activity(admin["id"], "user_banned", f"Banned user: {user_id}", request.remote_addr)
            elif key == 'status' and value == 'active':
                # Разбан пользователя
                bans = load_bans()
                if user_id in bans["user_bans"]:
                    bans["user_bans"].remove(user_id)
                    save_bans(bans)
                    log_activity(admin["id"], "user_unbanned", f"Unbanned user: {user_id}", request.remote_addr)
            else:
                user[key] = value
        
        save_database(db)
        log_activity(admin["id"], "user_updated", f"Updated user: {user_id}", request.remote_addr)
        
        return jsonify({
            "success": True,
            "message": "Пользователь обновлен"
        })
    
    elif request.method == 'DELETE':
        # Удаление пользователя (только супер-админ)
        if not admin.get('isSuperAdmin'):
            return jsonify({"error": "Требуются права супер-администратора"}), 403
        
        # Удаляем пользователя
        db["users"] = [u for u in db["users"] if u["id"] != user_id]
        
        # Удаляем связанный контент (опционально)
        # db["posts"] = [p for p in db["posts"] if p["userId"] != user_id]
        # db["videos"] = [v for v in db["videos"] if v["userId"] != user_id]
        
        save_database(db)
        log_activity(admin["id"], "user_deleted", f"Deleted user: {user_id}", request.remote_addr)
        
        return jsonify({
            "success": True,
            "message": "Пользователь удален"
        })

@app.route('/admin/api/posts', methods=['GET'])
@require_admin
def admin_get_posts(admin):
    """Получение списка постов"""
    db = load_database()
    
    # Фильтры
    status = request.args.get('status', 'all')  # all, reported, hidden
    limit = int(request.args.get('limit', 50))
    page = int(request.args.get('page', 1))
    
    posts = db["posts"]
    
    # Фильтрация по статусу
    if status == 'reported':
        reported_post_ids = [r["targetId"] for r in db["reports"] if r["type"] == "post"]
        posts = [p for p in posts if p["id"] in reported_post_ids]
    elif status == 'hidden':
        posts = [p for p in posts if p.get("hidden", False)]
    
    # Добавляем информацию о пользователях
    for post in posts:
        user = find_user_by_id(post["userId"], db)
        if user:
            post["user"] = {
                "id": user["id"],
                "username": user["username"],
                "displayName": user["displayName"]
            }
        
        # Количество репортов
        post["report_count"] = len([r for r in db["reports"] if r.get("targetId") == post["id"]])
    
    # Пагинация
    total = len(posts)
    start = (page - 1) * limit
    end = start + limit
    paginated_posts = posts[start:end]
    
    return jsonify({
        "success": True,
        "posts": paginated_posts,
        "total": total,
        "page": page,
        "pages": (total + limit - 1) // limit
    })

@app.route('/admin/api/posts/<post_id>', methods=['PUT', 'DELETE'])
@require_admin
def admin_manage_post(admin, post_id):
    """Управление постом"""
    db = load_database()
    post = find_post_by_id(post_id, db)
    
    if not post:
        return jsonify({"error": "Пост не найден"}), 404
    
    if request.method == 'PUT':
        data = request.json
        if not data:
            return jsonify({"error": "Нет данных"}), 400
        
        # Обновляем пост
        if 'hidden' in data:
            post["hidden"] = data['hidden']
            action = "скрыт" if data['hidden'] else "показан"
            log_activity(admin["id"], "post_updated", f"Post {action}: {post_id}", request.remote_addr)
        
        if 'content' in data and admin.get('isSuperAdmin'):
            post["content"] = data['content']
            log_activity(admin["id"], "post_content_updated", f"Updated content for post: {post_id}", request.remote_addr)
        
        save_database(db)
        
        return jsonify({
            "success": True,
            "message": "Пост обновлен"
        })
    
    elif request.method == 'DELETE':
        # Удаление поста
        db["posts"] = [p for p in db["posts"] if p["id"] != post_id]
        
        # Уменьшаем счетчик у пользователя
        user = find_user_by_id(post["userId"], db)
        if user and user["stats"]["posts"] > 0:
            user["stats"]["posts"] -= 1
        
        save_database(db)
        log_activity(admin["id"], "post_deleted", f"Deleted post: {post_id}", request.remote_addr)
        
        return jsonify({
            "success": True,
            "message": "Пост удален"
        })

@app.route('/admin/api/comments', methods=['GET'])
@require_admin
def admin_get_comments(admin):
    """Получение списка комментариев"""
    db = load_database()
    
    limit = int(request.args.get('limit', 50))
    page = int(request.args.get('page', 1))
    
    comments = db["comments"]
    
    # Добавляем информацию о пользователях
    for comment in comments:
        user = find_user_by_id(comment["userId"], db)
        if user:
            comment["user"] = {
                "id": user["id"],
                "username": user["username"],
                "displayName": user["displayName"]
            }
    
    # Пагинация
    total = len(comments)
    start = (page - 1) * limit
    end = start + limit
    paginated_comments = comments[start:end]
    
    return jsonify({
        "success": True,
        "comments": paginated_comments,
        "total": total,
        "page": page,
        "pages": (total + limit - 1) // limit
    })

@app.route('/admin/api/comments/<comment_id>', methods=['DELETE'])
@require_admin
def admin_delete_comment(admin, comment_id):
    """Удаление комментария"""
    db = load_database()
    
    # Находим комментарий
    comment = None
    for c in db["comments"]:
        if c["id"] == comment_id:
            comment = c
            break
    
    if not comment:
        return jsonify({"error": "Комментарий не найден"}), 404
    
    # Удаляем комментарий
    db["comments"] = [c for c in db["comments"] if c["id"] != comment_id]
    
    # Обновляем счетчики
    if "postId" in comment:
        post = find_post_by_id(comment["postId"], db)
        if post and post.get("comments", 0) > 0:
            post["comments"] -= 1
    elif "videoId" in comment:
        video = find_video_by_id(comment["videoId"], db)
        if video and video.get("comments", 0) > 0:
            video["comments"] -= 1
    
    save_database(db)
    log_activity(admin["id"], "comment_deleted", f"Deleted comment: {comment_id}", request.remote_addr)
    
    return jsonify({
        "success": True,
        "message": "Комментарий удален"
    })

@app.route('/admin/api/reports', methods=['GET', 'POST'])
@require_admin
def admin_reports(admin):
    """Управление репортами"""
    db = load_database()
    
    if request.method == 'GET':
        status = request.args.get('status', 'pending')
        limit = int(request.args.get('limit', 50))
        
        reports = [r for r in db["reports"] if r.get("status") == status]
        
        # Добавляем информацию
        for report in reports:
            # Пользователь, который пожаловался
            reporter = find_user_by_id(report["reporterId"], db)
            if reporter:
                report["reporter"] = {
                    "id": reporter["id"],
                    "displayName": reporter["displayName"]
                }
            
            # Цель жалобы
            if report["type"] == "post":
                target = find_post_by_id(report["targetId"], db)
                if target:
                    user = find_user_by_id(target["userId"], db)
                    report["target"] = {
                        "type": "post",
                        "content": target.get("content", "")[:100],
                        "user": user["displayName"] if user else "Неизвестно"
                    }
            elif report["type"] == "user":
                target = find_user_by_id(report["targetId"], db)
                if target:
                    report["target"] = {
                        "type": "user",
                        "username": target["username"],
                        "displayName": target["displayName"]
                    }
        
        return jsonify({
            "success": True,
            "reports": reports[:limit]
        })
    
    elif request.method == 'POST':
        data = request.json
        if not data:
            return jsonify({"error": "Нет данных"}), 400
        
        report_id = data.get('reportId')
        action = data.get('action')  # dismiss, warn, ban
        
        if not report_id or not action:
            return jsonify({"error": "Не указан ID репорта или действие"}), 400
        
        # Находим репорт
        report = None
        for r in db["reports"]:
            if r["id"] == report_id:
                report = r
                break
        
        if not report:
            return jsonify({"error": "Репорт не найден"}), 404
        
        # Выполняем действие
        if action == "dismiss":
            report["status"] = "dismissed"
            report["resolvedBy"] = admin["id"]
            report["resolvedAt"] = datetime.now().isoformat()
            message = "Репорт отклонен"
            
        elif action == "warn":
            report["status"] = "resolved"
            report["resolvedBy"] = admin["id"]
            report["resolvedAt"] = datetime.now().isoformat()
            
            # Отправляем предупреждение пользователю
            target_user = find_user_by_id(report["targetId"], db)
            if target_user:
                # Добавляем уведомление
                notification = {
                    "id": generate_id("notif"),
                    "userId": target_user["id"],
                    "type": "warning",
                    "title": "Предупреждение от администрации",
                    "message": f"Ваш контент был отмечен как нарушающий правила. {report.get('reason', '')}",
                    "createdAt": datetime.now().isoformat(),
                    "read": False
                }
                db["notifications"].append(notification)
            
            message = "Пользователю отправлено предупреждение"
            
        elif action == "ban":
            report["status"] = "resolved"
            report["resolvedBy"] = admin["id"]
            report["resolvedAt"] = datetime.now().isoformat()
            
            # Бан пользователя
            bans = load_bans()
            if report["targetId"] not in bans["user_bans"]:
                bans["user_bans"].append(report["targetId"])
                save_bans(bans)
            
            message = "Пользователь заблокирован"
        
        else:
            return jsonify({"error": "Неизвестное действие"}), 400
        
        save_database(db)
        log_activity(admin["id"], "report_resolved", f"Report {action}: {report_id}", request.remote_addr)
        
        return jsonify({
            "success": True,
            "message": message
        })

@app.route('/admin/api/bans', methods=['GET', 'POST', 'DELETE'])
@require_admin
def admin_bans(admin):
    """Управление банами"""
    bans = load_bans()
    
    if request.method == 'GET':
        ban_type = request.args.get('type', 'all')
        
        result = {}
        
        if ban_type in ['all', 'ip']:
            result["ip_bans"] = bans["ip_bans"]
        
        if ban_type in ['all', 'user']:
            result["user_bans"] = bans["user_bans"]
        
        if ban_type in ['all', 'temp']:
            result["temp_bans"] = bans["temp_bans"]
        
        return jsonify({
            "success": True,
            "bans": result
        })
    
    elif request.method == 'POST':
        data = request.json
        if not data:
            return jsonify({"error": "Нет данных"}), 400
        
        ban_type = data.get('type')  # ip, user, temp
        target = data.get('target')  # IP или user_id
        reason = data.get('reason', 'Нарушение правил')
        duration = data.get('duration', 0)  # в часах, 0 = перманентно
        
        if not ban_type or not target:
            return jsonify({"error": "Не указан тип бана или цель"}), 400
        
        if ban_type == "ip":
            # Бан по IP
            new_ban = {
                "ip": target,
                "reason": reason,
                "banned_by": admin["id"],
                "banned_at": datetime.now().isoformat()
            }
            
            if duration > 0:
                new_ban["expires"] = (datetime.now() + timedelta(hours=duration)).isoformat()
            
            bans["ip_bans"].append(new_ban)
            message = f"IP {target} заблокирован"
            
        elif ban_type == "user":
            # Бан пользователя
            if target not in bans["user_bans"]:
                bans["user_bans"].append(target)
            message = f"Пользователь {target} заблокирован"
            
        elif ban_type == "temp":
            # Временный бан
            expires = (datetime.now() + timedelta(hours=duration)).isoformat()
            bans["temp_bans"][target] = {
                "reason": reason,
                "banned_by": admin["id"],
                "banned_at": datetime.now().isoformat(),
                "expires": expires,
                "duration_hours": duration
            }
            message = f"Временный бан для {target} на {duration} часов"
        
        else:
            return jsonify({"error": "Неизвестный тип бана"}), 400
        
        save_bans(bans)
        log_activity(admin["id"], "ban_added", f"{ban_type} ban: {target}", request.remote_addr)
        
        return jsonify({
            "success": True,
            "message": message
        })
    
    elif request.method == 'DELETE':
        data = request.json or {}
        ban_type = data.get('type')
        target = data.get('target')
        
        if not ban_type or not target:
            return jsonify({"error": "Не указан тип бана или цель"}), 400
        
        if ban_type == "ip":
            bans["ip_bans"] = [b for b in bans["ip_bans"] if b["ip"] != target]
            message = f"IP {target} разблокирован"
            
        elif ban_type == "user":
            if target in bans["user_bans"]:
                bans["user_bans"].remove(target)
            message = f"Пользователь {target} разблокирован"
            
        elif ban_type == "temp":
            if target in bans["temp_bans"]:
                del bans["temp_bans"][target]
            message = f"Временный бан для {target} снят"
        
        save_bans(bans)
        log_activity(admin["id"], "ban_removed", f"{ban_type} ban removed: {target}", request.remote_addr)
        
        return jsonify({
            "success": True,
            "message": message
        })

@app.route('/admin/api/settings', methods=['GET', 'PUT'])
@require_super_admin
def admin_settings(admin):
    """Управление системными настройками"""
    db = load_database()
    
    if request.method == 'GET':
        return jsonify({
            "success": True,
            "settings": db.get("system_settings", {})
        })
    
    elif request.method == 'PUT':
        data = request.json
        if not data:
            return jsonify({"error": "Нет данных"}), 400
        
        # Обновляем настройки
        for key, value in data.items():
            if key in db["system_settings"]:
                db["system_settings"][key] = value
        
        save_database(db)
        log_activity(admin["id"], "settings_updated", "System settings updated", request.remote_addr)
        
        return jsonify({
            "success": True,
            "message": "Настройки обновлены"
        })

@app.route('/admin/api/logs', methods=['GET'])
@require_admin
def admin_logs(admin):
    """Получение логов"""
    db = load_database()
    
    action = request.args.get('action', '')
    user_id = request.args.get('user_id', '')
    limit = int(request.args.get('limit', 100))
    
    logs = db["admin_logs"]
    
    # Фильтрация
    if action:
        logs = [log for log in logs if log.get("action") == action]
    
    if user_id:
        logs = [log for log in logs if log.get("user_id") == user_id]
    
    # Сортируем по времени (новые сначала)
    logs.sort(key=lambda x: x["timestamp"], reverse=True)
    
    return jsonify({
        "success": True,
        "logs": logs[:limit],
        "total": len(logs)
    })

@app.route('/admin/api/stats/overview')
@require_admin
def admin_stats_overview(admin):
    """Общая статистика"""
    db = load_database()
    
    # Статистика за последние 30 дней
    thirty_days_ago = datetime.now() - timedelta(days=30)
    
    # Новые пользователи по дням
    users_by_day = {}
    for user in db["users"]:
        if datetime.fromisoformat(user["createdAt"]) > thirty_days_ago:
            date = user["createdAt"][:10]  # YYYY-MM-DD
            users_by_day[date] = users_by_day.get(date, 0) + 1
    
    # Новые посты по дням
    posts_by_day = {}
    for post in db["posts"]:
        if datetime.fromisoformat(post["createdAt"]) > thirty_days_ago:
            date = post["createdAt"][:10]
            posts_by_day[date] = posts_by_day.get(date, 0) + 1
    
    # Активные пользователи (за последние 7 дней)
    week_ago = datetime.now() - timedelta(days=7)
    active_users = set()
    for log in db["admin_logs"]:
        if datetime.fromisoformat(log["timestamp"]) > week_ago:
            active_users.add(log["user_id"])
    
    return jsonify({
        "success": True,
        "users_by_day": users_by_day,
        "posts_by_day": posts_by_day,
        "active_users": len(active_users),
        "total_likes": sum(len(p.get("likes", [])) for p in db["posts"]) + 
                      sum(len(v.get("likes", [])) for v in db["videos"]),
        "total_comments": len(db["comments"]),
        "avg_posts_per_user": len(db["posts"]) / max(len(db["users"]), 1)
    })

# ==================== ОСНОВНОЕ API С ЗАЩИТОЙ ОТ СПАМА ====================

@app.route('/api/register', methods=['POST'])
@spam_protection("requests")
def api_register():
    """Регистрация с защитой от спама"""
    db = load_database()
    data = request.json
    
    # Проверка на обслуживание системы
    if db.get("system_settings", {}).get("maintenance", False):
        return jsonify({"error": "Система на обслуживании. Попробуйте позже."}), 503
    
    # Проверка на включенную регистрацию
    if not db.get("system_settings", {}).get("registration_enabled", True):
        return jsonify({"error": "Регистрация временно отключена"}), 403
    
    required_fields = ['username', 'displayName', 'password', 'email', 'emoji']
    for field in required_fields:
        if field not in data or not data[field]:
            return jsonify({"error": f"Отсутствует обязательное поле: {field}"}), 400
    
    # Проверка на спам в username/email
    spam_score = 0
    spam_domains = ['temp-mail', '10minutemail', 'guerrillamail', 'mailinator']
    
    for domain in spam_domains:
        if domain in data['email'].lower():
            spam_score += 3
    
    if anti_spam.check_content_spam(data['username']):
        spam_score += 2
    
    if anti_spam.check_content_spam(data['displayName']):
        spam_score += 1
    
    if spam_score >= 3:
        log_activity("SYSTEM", "spam_registration", 
                    f"Spam registration attempt: {data['email']}", request.remote_addr)
        return jsonify({"error": "Обнаружены признаки спама. Регистрация отклонена."}), 403
    
    # Проверка уникальности username и email
    if find_user_by_username(data['username'], db):
        return jsonify({"error": "Имя пользователя уже существует"}), 400
    
    for user in db["users"]:
        if user["email"] == data['email']:
            return jsonify({"error": "Email уже зарегистрирован"}), 400
    
    # Проверка сложности пароля
    if len(data['password']) < MIN_PASSWORD_LENGTH:
        return jsonify({"error": f"Пароль должен быть не менее {MIN_PASSWORD_LENGTH} символов"}), 400
    
    # Создание нового пользователя
    new_user = {
        "id": generate_id("user"),
        "username": data['username'],
        "displayName": data['displayName'],
        "email": data['email'],
        "password": hash_password(data['password']),
        "emoji": data['emoji'],
        "bio": "",
        "createdAt": datetime.now().isoformat(),
        "isAdmin": False,
        "isSuperAdmin": False,
        "isVerified": False,
        "notifications": 0,
        "clan": None,
        "followers": [],
        "following": [],
        "stats": {
            "posts": 0,
            "videos": 0,
            "stories": 0,
            "likes": 0
        },
        "settings": {
            "theme": "dark",
            "language": "ru",
            "notifications": True,
            "privacy": "public"
        },
        "status": "active",
        "last_active": datetime.now().isoformat()
    }
    
    db["users"].append(new_user)
    save_database(db)
    
    log_activity(new_user["id"], "user_registered", "New user registered", request.remote_addr)
    
    # Удаляем пароль из ответа
    user_response = new_user.copy()
    del user_response['password']
    
    return jsonify({
        "success": True,
        "user": user_response,
        "message": "Регистрация успешна!"
    })

@app.route('/api/posts', methods=['POST'])
@spam_protection("posts")
def api_create_post():
    """Создание поста с защитой от спама"""
    db = load_database()
    data = request.json
    
    if not data:
        return jsonify({"error": "Нет данных"}), 400
    
    if 'userId' not in data:
        return jsonify({"error": "Пользователь не авторизован"}), 401
    
    # Проверка бана пользователя
    banned, reason = is_banned(user_id=data['userId'])
    if banned:
        return jsonify({"error": f"Аккаунт заблокирован: {reason}"}), 403
    
    user = find_user_by_id(data['userId'], db)
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404
    
    # Проверка на спам в контенте
    if 'content' in data and anti_spam.check_content_spam(data['content'], data['userId']):
        log_activity(data['userId'], "spam_post_blocked", 
                    "Post blocked as spam", request.remote_addr)
        return jsonify({"error": "Сообщение содержит признаки спама"}), 403
    
    # Проверка лимита постов
    if not anti_spam.check_rate_limit(request.remote_addr, "posts"):
        log_activity(data['userId'], "post_limit_exceeded", 
                    "Post limit exceeded", request.remote_addr)
        return jsonify({"error": "Превышен лимит постов на сегодня"}), 429
    
    # Создание поста
    new_post = {
        "id": generate_id("post"),
        "userId": data['userId'],
        "content": data.get('content', ''),
        "media": data.get('media', []),
        "visibility": data.get('visibility', 'public'),
        "createdAt": datetime.now().isoformat(),
        "updatedAt": datetime.now().isoformat(),
        "likes": [],
        "comments": 0,
        "shares": 0,
        "views": 0,
        "tags": data.get('tags', []),
        "hidden": False,
        "moderated": not db.get("system_settings", {}).get("content_moderation", True)
    }
    
    db["posts"].insert(0, new_post)
    user["stats"]["posts"] += 1
    save_database(db)
    
    log_activity(data['userId'], "post_created", f"Post created: {new_post['id']}", request.remote_addr)
    
    return jsonify({
        "success": True,
        "post": new_post,
        "message": "Пост опубликован"
    })

@app.route('/api/comments', methods=['POST'])
@spam_protection("comments")
def api_create_comment():
    """Создание комментария с защитой от спама"""
    db = load_database()
    data = request.json
    
    if not data:
        return jsonify({"error": "Нет данных"}), 400
    
    required_fields = ['userId', 'text']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Отсутствует обязательное поле: {field}"}), 400
    
    # Проверка бана пользователя
    banned, reason = is_banned(user_id=data['userId'])
    if banned:
        return jsonify({"error": f"Аккаунт заблокирован: {reason}"}), 403
    
    # Проверка на спам
    if anti_spam.check_content_spam(data['text'], data['userId']):
        log_activity(data['userId'], "spam_comment_blocked", 
                    "Comment blocked as spam", request.remote_addr)
        return jsonify({"error": "Комментарий содержит признаки спама"}), 403
    
    user = find_user_by_id(data['userId'], db)
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404
    
    # Создание комментария
    new_comment = {
        "id": generate_id("comment"),
        "userId": data['userId'],
        "text": data['text'],
        "createdAt": datetime.now().isoformat(),
        "likes": [],
        "reported": False
    }
    
    # Определяем тип цели
    if 'postId' in data:
        new_comment["postId"] = data['postId']
        post = find_post_by_id(data['postId'], db)
        if post:
            post["comments"] += 1
    elif 'videoId' in data:
        new_comment["videoId"] = data['videoId']
        video = find_video_by_id(data['videoId'], db)
        if video:
            video["comments"] += 1
    else:
        return jsonify({"error": "Должен быть указан postId или videoId"}), 400
    
    db["comments"].append(new_comment)
    save_database(db)
    
    log_activity(data['userId'], "comment_created", 
                f"Comment created: {new_comment['id']}", request.remote_addr)
    
    return jsonify({
        "success": True,
        "comment": new_comment
    })

@app.route('/api/report', methods=['POST'])
@spam_protection("requests")
def api_report():
    """Репорт контента или пользователя"""
    db = load_database()
    data = request.json
    
    if not data:
        return jsonify({"error": "Нет данных"}), 400
    
    required_fields = ['reporterId', 'targetId', 'type', 'reason']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Отсутствует обязательное поле: {field}"}), 400
    
    # Проверка бана репортёра
    banned, reason = is_banned(user_id=data['reporterId'])
    if banned:
        return jsonify({"error": f"Аккаунт заблокирован: {reason}"}), 403
    
    # Создание репорта
    new_report = {
        "id": generate_id("report"),
        "reporterId": data['reporterId'],
        "targetId": data['targetId'],
        "type": data['type'],  # post, comment, user, video
        "reason": data['reason'],
        "details": data.get('details', ''),
        "status": "pending",
        "createdAt": datetime.now().isoformat()
    }
    
    db["reports"].append(new_report)
    save_database(db)
    
    log_activity(data['reporterId'], "report_created", 
                f"Report created: {data['type']} {data['targetId']}", request.remote_addr)
    
    # Уведомление администраторов
    admins = [u for u in db["users"] if u.get('isAdmin')]
    for admin in admins:
        notification = {
            "id": generate_id("notif"),
            "userId": admin["id"],
            "type": "report",
            "title": "Новый репорт",
            "message": f"Новый репорт на {data['type']}. Причина: {data['reason'][:50]}...",
            "createdAt": datetime.now().isoformat(),
            "read": False,
            "data": {"reportId": new_report["id"]}
        }
        db["notifications"].append(notification)
    
    save_database(db)
    
    return jsonify({
        "success": True,
        "message": "Жалоба отправлена администрации"
    })

# ==================== ОСНОВНЫЕ МАРШРУТЫ ====================

@app.route('/')
def index():
    try:
        with open('index.html', 'r', encoding='utf-8') as f:
            html_content = f.read()
        return html_content
    except:
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>ITD Social Network</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    margin: 0;
                    color: white;
                }
                .container {
                    text-align: center;
                    padding: 2rem;
                }
                h1 {
                    font-size: 3rem;
                    margin-bottom: 1rem;
                }
                p {
                    font-size: 1.2rem;
                    opacity: 0.9;
                    margin-bottom: 2rem;
                }
                .links {
                    display: flex;
                    gap: 1rem;
                    justify-content: center;
                }
                .btn {
                    padding: 1rem 2rem;
                    background: white;
                    color: #667eea;
                    text-decoration: none;
                    border-radius: 5px;
                    font-weight: bold;
                    transition: transform 0.3s;
                }
                .btn:hover {
                    transform: translateY(-2px);
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🚀 ITD Social Network</h1>
                <p>Социальная сеть нового поколения с админ панелью</p>
                <div class="links">
                    <a href="/admin" class="btn">Админ панель</a>
                </div>
            </div>
        </body>
        </html>
        '''

# Статические файлы
@app.route('/media/<path:path>')
def serve_media(path):
    return send_from_directory(MEDIA_FOLDER, path)

@app.route('/uploads/<path:path>')
def serve_upload(path):
    return send_from_directory(UPLOAD_FOLDER, path)

# ==================== ЗАПУСК СЕРВЕРА ====================

if __name__ == '__main__':
    # Инициализация базы данных
    with app.app_context():
        init_database()
    
    print("=" * 60)
    print("🚀 ITD Social Network Server with Admin Panel")
    print("=" * 60)
    print(f"📁 Database: {DB_FILE}")
    print(f"📁 Media folder: {MEDIA_FOLDER}")
    print(f"📁 Logs folder: {LOGS_FOLDER}")
    print(f"🔒 Security features: Anti-spam, Rate limiting, Admin panel")
    print("\n🌐 Admin Panel URLs:")
    print("  GET  /admin              - Админ панель")
    print("  GET  /admin/login        - Вход для администраторов")
    print("  GET  /admin/api/*        - API для админ панели")
    print("\n🔧 Default admin credentials:")
    print("  Username: admin")
    print("  Password: admin123")
    print("  ⚠️ СМЕНИТЕ ПАРОЛЬ ПРИ ПЕРВОМ ВХОДЕ!")
    print("=" * 60)
    
    # Запускаем сервер
    app.run(host='0.0.0.0', port=5000, debug=True)