import base64
import json
import json
import os
import re
import uuid
from urllib.parse import urlparse
from datetime import datetime
from functools import wraps

from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask import (
    Flask,
    Response,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    stream_with_context,
    url_for,
)
from flask_login import (LoginManager, UserMixin, current_user, login_required,
                          login_user, logout_user)
from flask_sqlalchemy import SQLAlchemy
from pypdf import PdfReader
import requests
from sqlalchemy import text
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
default_base_dir = app.root_path
if os.path.isdir("/home/studiequiz/mysite"):
    default_base_dir = "/home/studiequiz/mysite"
base_dir = os.getenv("BASE_DIR", default_base_dir)
load_dotenv(os.path.join(base_dir, ".env"))
app.config["BASE_DIR"] = base_dir
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-change-me")
db_path = os.path.join(base_dir, "instance", "app.db")
database_url = os.getenv("DATABASE_URL", "")
if database_url.startswith("sqlite:"):
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["OPENROUTER_API_KEY"] = os.getenv("OPENROUTER_API_KEY", "")
app.config["OPENROUTER_MODEL"] = os.getenv("OPENROUTER_MODEL", "openrouter/auto")
app.config["OPENROUTER_HELP_MODEL"] = os.getenv(
    "OPENROUTER_HELP_MODEL", "mistralai/mistral-7b-instruct:free"
)
app.config["UPLOAD_FOLDER"] = os.path.join(base_dir, "uploads")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
app.config["UPLOAD_RETENTION_SECONDS"] = 24 * 60 * 60
app.config["QUESTION_MAX"] = int(os.getenv("QUESTION_MAX", "20"))
app.config["MAINTENANCE_MODE"] = os.getenv("MAINTENANCE_MODE", "off").lower() == "on"
app.config["ADMIN_USERNAME"] = os.getenv("ADMIN_USERNAME", "")
app.config["ADMIN_PASSWORD"] = os.getenv("ADMIN_PASSWORD", "")
app.config["GITHUB_CLIENT_ID"] = os.getenv("GITHUB_CLIENT_ID", "")
app.config["GITHUB_CLIENT_SECRET"] = os.getenv("GITHUB_CLIENT_SECRET", "")
app.config["GITHUB_TEACHER_ORGS"] = os.getenv("GITHUB_TEACHER_ORGS", "")
app.config["GITHUB_STUDENT_ORGS"] = os.getenv("GITHUB_STUDENT_ORGS", "")
app.config["GITHUB_TEACHER_DOMAINS"] = os.getenv("GITHUB_TEACHER_DOMAINS", "")
app.config["GITHUB_STUDENT_DOMAINS"] = os.getenv("GITHUB_STUDENT_DOMAINS", "")
app.config["GITHUB_DEFAULT_ROLE"] = os.getenv("GITHUB_DEFAULT_ROLE", "student")

os.makedirs(os.path.dirname(db_path), exist_ok=True)
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
oauth = OAuth(app)

if app.config["GITHUB_CLIENT_ID"] and app.config["GITHUB_CLIENT_SECRET"]:
    oauth.register(
        name="github",
        client_id=app.config["GITHUB_CLIENT_ID"],
        client_secret=app.config["GITHUB_CLIENT_SECRET"],
        authorize_url="https://github.com/login/oauth/authorize",
        access_token_url="https://github.com/login/oauth/access_token",
        api_base_url="https://api.github.com/",
        client_kwargs={"scope": "read:user user:email"},
    )


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    nickname = db.Column(db.String(120), nullable=True)
    profile_image_base64 = db.Column(db.Text, nullable=True)
    profile_image_mime = db.Column(db.String(120), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    quizzes = db.relationship("Quiz", backref="teacher", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    subject = db.Column(db.String(120), nullable=True)
    chapter = db.Column(db.String(120), nullable=False)
    source_text = db.Column(db.Text, nullable=False)
    questions = db.Column(db.Text, nullable=False)
    published = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    teacher_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    class_id = db.Column(db.Integer, db.ForeignKey("classroom.id"), nullable=True)


class QuizAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey("quiz.id"), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    score_correct = db.Column(db.Integer, nullable=False)
    score_total = db.Column(db.Integer, nullable=False)
    results_json = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    quiz = db.relationship("Quiz", backref="attempts", lazy=True)
    student = db.relationship("User", backref="quiz_attempts", lazy=True)


class Classroom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    code = db.Column(db.String(20), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    teacher_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    teacher = db.relationship("User", backref="classes", lazy=True)
    quizzes = db.relationship("Quiz", backref="classroom", lazy=True)


class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    class_id = db.Column(db.Integer, db.ForeignKey("classroom.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    student = db.relationship("User", backref="enrollments", lazy=True)
    classroom = db.relationship("Classroom", backref="enrollments", lazy=True)


@app.errorhandler(413)
def request_entity_too_large(error):
    flash("Je boek is te groot.", "error")
    return (
        render_template(
            "create_quiz.html",
            action_url=url_for("create_quiz"),
            submit_label="Quiz opslaan",
            classes=[],
            title="",
            chapter="",
            source_text="",
            questions="",
            show_questions=False,
            headings=[],
            published=False,
        ),
        413,
    )


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if app.config.get("MAINTENANCE_MODE") and not session.get("is_admin"):
        flash("Maintenance", "error")
        return redirect(url_for("index"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "").strip().lower()

        if role not in {"teacher", "student"}:
            flash("Kies een geldige rol.", "error")
            return redirect(url_for("signup"))

        if not name or not email or not password:
            flash("Alle velden zijn verplicht.", "error")
            return redirect(url_for("signup"))

        existing = User.query.filter_by(email=email).first()
        if existing:
            flash("E-mailadres is al geregistreerd.", "error")
            return redirect(url_for("signup"))

        user = User(name=name, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Account aangemaakt. Log in.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if app.config.get("MAINTENANCE_MODE") and not session.get("is_admin"):
        flash("Maintenance", "error")
        return redirect(url_for("index"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            flash("Ongeldig e-mailadres of wachtwoord.", "error")
            return redirect(url_for("login"))

        login_user(user)
        if user.role == "teacher":
            return redirect(url_for("teacher_dashboard"))
        return redirect(url_for("student_dashboard"))

    return render_template("login.html")


@app.route("/login/github")
def login_github():
    if app.config.get("MAINTENANCE_MODE") and not session.get("is_admin"):
        flash("Maintenance", "error")
        return redirect(url_for("index"))
    if not is_github_sso_configured():
        flash("GitHub SSO is niet geconfigureerd.", "error")
        return redirect(url_for("login"))
    client = oauth.create_client("github")
    if client is None:
        flash("GitHub SSO is niet beschikbaar.", "error")
        return redirect(url_for("login"))
    redirect_uri = url_for("github_callback", _external=True)
    return client.authorize_redirect(redirect_uri)


@app.route("/auth/github/callback")
def github_callback():
    if not is_github_sso_configured():
        flash("GitHub SSO is niet geconfigureerd.", "error")
        return redirect(url_for("login"))
    client = oauth.create_client("github")
    if client is None:
        flash("GitHub SSO is niet beschikbaar.", "error")
        return redirect(url_for("login"))

    try:
        token = client.authorize_access_token()
    except Exception:
        flash("GitHub inloggen mislukt.", "error")
        return redirect(url_for("login"))

    user_info = {}
    try:
        response = client.get("user", token=token)
        user_info = response.json()
    except Exception:
        user_info = {}

    if not isinstance(user_info, dict):
        user_info = {}

    email = str(user_info.get("email", "")).strip().lower()
    if not email:
        try:
            emails_response = client.get("user/emails", token=token)
            emails = emails_response.json()
        except Exception:
            emails = []
        if isinstance(emails, list):
            primary = None
            for entry in emails:
                if not isinstance(entry, dict):
                    continue
                if entry.get("primary") and entry.get("verified"):
                    primary = entry.get("email")
                    break
            if not primary:
                for entry in emails:
                    if not isinstance(entry, dict):
                        continue
                    if entry.get("verified"):
                        primary = entry.get("email")
                        break
            if primary:
                email = str(primary).strip().lower()

    if not email:
        flash("GitHub-profiel bevat geen e-mailadres.", "error")
        return redirect(url_for("login"))

    role = resolve_github_role(user_info, email, client, token)
    if not role:
        flash("GitHub-rol kon niet worden bepaald.", "error")
        return redirect(url_for("login"))

    user = User.query.filter_by(email=email).first()
    if user:
        if user.role != role:
            flash("GitHub-rol komt niet overeen met je account.", "error")
            return redirect(url_for("login"))
        if not user.name:
            user.name = sso_display_name(user_info, email)
            db.session.commit()
    else:
        user = User(name=sso_display_name(user_info, email), email=email, role=role)
        user.set_password(uuid.uuid4().hex)
        db.session.add(user)
        db.session.commit()

    login_user(user)
    if user.role == "teacher":
        return redirect(url_for("teacher_dashboard"))
    return redirect(url_for("student_dashboard"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Uitgelogd.", "success")
    return redirect(url_for("index"))


def require_teacher():
    if current_user.role != "teacher":
        flash("Alleen docenten hebben toegang.", "error")
        return False
    return True


def is_github_sso_configured():
    if not (
        app.config.get("GITHUB_CLIENT_ID") and app.config.get("GITHUB_CLIENT_SECRET")
    ):
        return False
    return oauth.create_client("github") is not None


@app.context_processor
def inject_globals():
    return {
        "maintenance_mode": app.config.get("MAINTENANCE_MODE", False),
        "question_max": app.config.get("QUESTION_MAX", 20),
        "is_admin": session.get("is_admin", False),
        "github_sso_enabled": is_github_sso_configured(),
    }


def parse_domain_list(raw_value):
    return {item.strip().lower() for item in raw_value.split(",") if item.strip()}


def parse_org_list(raw_value):
    return {item.strip() for item in raw_value.split(",") if item.strip()}


def github_user_in_orgs(client, token, orgs):
    if not orgs:
        return False
    response = client.get("user/orgs", token=token)
    if response.status_code != 200:
        return False
    try:
        entries = response.json()
    except ValueError:
        return False
    if not isinstance(entries, list):
        return False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        login = str(entry.get("login", "")).strip()
        if login in orgs:
            return True
    return False


def resolve_github_role(user_info, email, client, token):
    domain = email.split("@")[-1].lower() if "@" in email else ""
    teacher_domains = parse_domain_list(app.config.get("GITHUB_TEACHER_DOMAINS", ""))
    student_domains = parse_domain_list(app.config.get("GITHUB_STUDENT_DOMAINS", ""))
    if domain:
        if domain in teacher_domains:
            return "teacher"
        if domain in student_domains:
            return "student"

    teacher_orgs = parse_org_list(app.config.get("GITHUB_TEACHER_ORGS", ""))
    student_orgs = parse_org_list(app.config.get("GITHUB_STUDENT_ORGS", ""))
    if github_user_in_orgs(client, token, teacher_orgs):
        return "teacher"
    if github_user_in_orgs(client, token, student_orgs):
        return "student"
    default_role = str(app.config.get("GITHUB_DEFAULT_ROLE", "")).strip().lower()
    if default_role in {"teacher", "student"}:
        return default_role
    return ""


def sso_display_name(user_info, fallback_email):
    name = str(user_info.get("name", "")).strip()
    if not name:
        name = str(user_info.get("preferred_username", "")).strip()
    if not name:
        given = str(user_info.get("given_name", "")).strip()
        family = str(user_info.get("family_name", "")).strip()
        name = " ".join(part for part in [given, family] if part).strip()
    if not name:
        name = fallback_email.split("@", 1)[0]
    return name


def generate_questions_from_text(source_text, chapter, subject, question_count):
    api_key = app.config.get("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError("OpenRouter API-sleutel ontbreekt.")

    max_chars = 80000
    trimmed_text = source_text
    if len(trimmed_text) > max_chars:
        trimmed_text = trimmed_text[:max_chars]

    subject_value = (subject or "").strip()
    subject_hint = f"Vak: {subject_value}\n" if subject_value else ""
    focus_hint = ""
    subject_lower = subject_value.lower()
    if "grammatica" in subject_lower:
        focus_hint = (
            "Focus op grammatica: regels, zinsbouw, vervoegingen en korte oefeningen. "
        )
    elif "schrijven" in subject_lower:
        focus_hint = (
            "Focus op schrijven: tekststructuur, stijl, woordkeuze en korte schrijfopdrachten. "
        )

    prompt = (
        "Je helpt een docent met het maken van een quiz voor middelbare scholieren. "
        f"Genereer {question_count} korte, duidelijke vragen op basis van de tekst. "
        f"{focus_hint}"
        "Geef ALLEEN geldige JSON: een array met objecten. "
        "Elke vraag heeft de sleutels 'question' en 'answer'. "
        "Als een vraag VISUEEL is of data vereist (bijv. kleuren, vormen, grafieken, tabellen, pie charts, diagrammen, kaarten), "
        "MOET je 'image_url' toevoegen met een directe https-link naar een publiek toegankelijke afbeelding die de vraag ondersteunt. "
        "Gebruik alleen directe afbeeldingslinks van upload.wikimedia.org (Wikimedia Commons), geen pagina-URL's. "
        "Vermijd sites die hotlinking blokkeren (zoals researchgate, pinterest, google images). "
        "Gebruik ook een afbeelding voor wiskundevragen die om een figuur, grafiek of tabel vragen. "
        "Geen markdown, geen uitleg, geen extra tekst. "
        "Houd antwoorden kort en exact. "
        f"{subject_hint}"
        f"Hoofdstuk: {chapter}\n"
        f"Tekst (mogelijk ingekort):\n{trimmed_text}"
    )

    response = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://localhost:5000",
            "X-Title": "StudieQuiz",
        },
        json={
            "model": app.config["OPENROUTER_MODEL"],
            "messages": [
                {"role": "system", "content": "Je bent een behulpzame quizschrijver."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.3,
        },
        timeout=60,
    )

    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        raise ValueError(
            f"OpenRouter request failed ({response.status_code}): {response.text}"
        ) from exc
    data = response.json()
    content = data["choices"][0]["message"]["content"].strip()
    return content


ASSIGNMENT_KEYWORDS = {
    "assignment",
    "assignments",
    "exercise",
    "exercises",
    "oefening",
    "oefeningen",
    "opdracht",
    "opdrachten",
    "vragen",
    "vraag",
}


def normalize_heading(text):
    return re.sub(r"\s+", " ", text.strip().lower())


def is_assignment_heading(text):
    lowered = normalize_heading(text)
    return any(keyword in lowered for keyword in ASSIGNMENT_KEYWORDS)


def looks_like_heading(text):
    if not text:
        return False
    lowered = normalize_heading(text)
    if is_assignment_heading(lowered):
        return False
    if len(lowered) > 140:
        return False
    word_count = len([part for part in lowered.split(" ") if part])
    if word_count > 14:
        return False
    if lowered.startswith(("hoofdstuk", "chapter", "paragraaf", "section")):
        return True
    numbered_match = re.match(r"^(\d+(?:[.,]\d+){0,3}|[ivxlcdm]+)\b(.*)$", lowered)
    if not numbered_match:
        return False
    remainder = numbered_match.group(2).strip(" -–—:\t")
    if not remainder:
        return False
    if not re.search(r"[a-z]", remainder):
        return False
    letter_count = len(re.findall(r"[a-z]", remainder))
    if letter_count < 3:
        return False
    return True


def extract_chapter_headings(source_text):
    headings = []
    seen = set()
    pattern = re.compile(
        r"^(\s*(?:hoofdstuk|chapter|paragraaf|section)\s*"
        r"(?:[0-9]+(?:[.,]\d+){0,3}|[IVXLCDM]+)\b[^\n]{0,80}"
        r"|\s*(?:[0-9]+(?:[.,]\d+){0,3}|[IVXLCDM]+)\b\s*[^\n]{0,80})",
        re.IGNORECASE | re.MULTILINE,
    )

    for line in source_text.splitlines():
        cleaned = line.strip()
        if not cleaned:
            continue
        if not looks_like_heading(cleaned):
            continue
        key = normalize_heading(cleaned)
        if key not in seen:
            headings.append(cleaned)
            seen.add(key)

    for match in pattern.finditer(source_text):
        cleaned = match.group(0).strip()
        if not cleaned:
            continue
        if not looks_like_heading(cleaned):
            continue
        key = normalize_heading(cleaned)
        if key not in seen:
            headings.append(cleaned)
            seen.add(key)
    ai_headings = extract_chapter_headings_with_ai(source_text)
    if ai_headings:
        ai_keys = {normalize_heading(item) for item in ai_headings}
        confirmed = [item for item in headings if normalize_heading(item) in ai_keys]
        if confirmed:
            return confirmed
        return ai_headings

    return headings


def extract_chapter_text_by_heading(source_text, chapter_title):
    if not chapter_title:
        return ""

    target = normalize_heading(chapter_title)
    lines = source_text.splitlines()
    start_idx = None

    for idx, line in enumerate(lines):
        cleaned = line.strip()
        if not cleaned:
            continue
        if target in normalize_heading(cleaned):
            start_idx = idx
            break

    if start_idx is not None:
        for idx in range(start_idx + 1, len(lines)):
            next_line = lines[idx].strip()
            if not next_line:
                continue
            if looks_like_heading(next_line):
                return "\n".join(lines[start_idx:idx]).strip()

        return "\n".join(lines[start_idx:]).strip()

    pattern = re.compile(
        r"(hoofdstuk|chapter|paragraaf|section)\s*"
        r"([0-9]+(?:[.,]\d+){0,3}|[IVXLCDM]+)\b[^\n]{0,80}"
        r"|^\s*(?:[0-9]+(?:[.,]\d+){0,3}|[IVXLCDM]+)\b\s*[^\n]{0,80}",
        re.IGNORECASE | re.MULTILINE,
    )
    matches = list(pattern.finditer(source_text))
    if not matches:
        return ""

    for idx, match in enumerate(matches):
        raw_heading = match.group(0).strip()
        if not raw_heading or not looks_like_heading(raw_heading):
            continue
        heading = normalize_heading(raw_heading)
        if heading == target or target in heading:
            start = match.start()
            end = matches[idx + 1].start() if idx + 1 < len(matches) else len(source_text)
            return source_text[start:end].strip()

    return ""


def extract_chapter_text(source_text, chapter_title):
    direct = extract_chapter_text_by_heading(source_text, chapter_title)
    if direct:
        return direct

    ai_heading = find_best_heading_with_ai(source_text, chapter_title)
    if not ai_heading:
        return ""
    if normalize_heading(ai_heading) == normalize_heading(chapter_title):
        return ""

    return extract_chapter_text_by_heading(source_text, ai_heading)


def parse_chapter_selection(form):
    selections = [item.strip() for item in form.getlist("chapter") if item.strip()]
    manual_raw = form.get("chapter_manual", "").strip()
    manual_items = [item.strip() for item in manual_raw.split(",") if item.strip()]

    ordered = []
    seen = set()
    for item in selections + manual_items:
        key = normalize_heading(item)
        if key and key not in seen:
            ordered.append(item)
            seen.add(key)

    return ordered, manual_raw


def parse_question_count(form):
    raw = form.get("question_count", "").strip()
    if not raw:
        return 8
    try:
        value = int(raw)
    except ValueError:
        return 8
    max_value = app.config.get("QUESTION_MAX", 20)
    if not isinstance(max_value, int) or max_value < 1:
        max_value = 20
    return max(1, min(value, max_value))


def extract_chapters_text(source_text, chapter_titles):
    parts = []
    seen = set()
    for title in chapter_titles:
        if not title:
            continue
        chapter_text = extract_chapter_text(source_text, title)
        key = normalize_heading(title)
        if chapter_text and key not in seen:
            parts.append(chapter_text)
            seen.add(key)

    return "\n\n".join(parts).strip()


def extract_json_array(text):
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        cleaned = cleaned.replace("json", "", 1).strip()

    start = cleaned.find("[")
    end = cleaned.rfind("]")
    if start == -1 or end == -1 or end < start:
        return ""
    return cleaned[start : end + 1]


def extract_heading_list(text):
    cleaned = text.strip()
    if not cleaned:
        return []
    json_blob = extract_json_array(cleaned)
    if not json_blob:
        return []
    try:
        data = json.loads(json_blob)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    headings = []
    seen = set()
    for item in data:
        if not isinstance(item, str):
            continue
        cleaned_item = item.strip()
        if not cleaned_item:
            continue
        if is_assignment_heading(cleaned_item):
            continue
        if not looks_like_heading(cleaned_item):
            continue
        key = normalize_heading(cleaned_item)
        if key and key not in seen:
            headings.append(cleaned_item)
            seen.add(key)
    return headings


def extract_chapter_headings_with_ai(source_text):
    api_key = app.config.get("OPENROUTER_API_KEY")
    if not api_key:
        return []
    if not source_text.strip():
        return []

    max_chars = 40000
    trimmed_text = source_text[:max_chars]
    prompt = (
        "Je extraheert hoofdstuktitels uit een schoolboek. "
        "Geef ALLEEN geldige JSON-array met strings. "
        "Gebruik exacte hoofdstuktitels zoals in de tekst. "
        "Focus op genummerde koppen (bijv. 1, 1.2, 2.3.4, IV) en labels als "
        "Hoofdstuk, Chapter, Paragraaf, Section. "
        "Negeer opdrachten/oefeningen/vragen. "
        "Geen uitleg, geen markdown. "
        "Tekst:\n" + trimmed_text
    )

    response = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://localhost:5000",
            "X-Title": "StudieQuiz",
        },
        json={
            "model": app.config["OPENROUTER_MODEL"],
            "messages": [
                {"role": "system", "content": "Je bent een nauwkeurige tekstanalist."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
        },
        timeout=60,
    )

    try:
        response.raise_for_status()
    except requests.HTTPError:
        return []

    try:
        data = response.json()
    except ValueError:
        return []
    content = str(data.get("choices", [{}])[0].get("message", {}).get("content", "")).strip()
    return extract_heading_list(content)


def find_best_heading_with_ai(source_text, desired_title):
    api_key = app.config.get("OPENROUTER_API_KEY")
    if not api_key:
        return ""
    if not source_text.strip() or not desired_title.strip():
        return ""

    max_chars = 40000
    trimmed_text = source_text[:max_chars]
    prompt = (
        "Je vindt de exacte hoofdstuktitel in de tekst die het best past bij: "
        f"'{desired_title}'. "
        "Geef ALLEEN geldige JSON-array met 0 of 1 string. "
        "De string moet een exacte regel/koptitel uit de tekst zijn. "
        "Negeer opdrachten/oefeningen/vragen. "
        "Geen uitleg, geen markdown. "
        "Tekst:\n" + trimmed_text
    )

    response = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://localhost:5000",
            "X-Title": "StudieQuiz",
        },
        json={
            "model": app.config["OPENROUTER_MODEL"],
            "messages": [
                {"role": "system", "content": "Je bent een nauwkeurige tekstanalist."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
        },
        timeout=60,
    )

    try:
        response.raise_for_status()
    except requests.HTTPError:
        return ""

    try:
        data = response.json()
    except ValueError:
        return ""
    content = str(data.get("choices", [{}])[0].get("message", {}).get("content", "")).strip()
    headings = extract_heading_list(content)
    return headings[0] if headings else ""


BLOCKED_IMAGE_HOSTS = {
    "researchgate.net",
    "www.researchgate.net",
}

PROFILE_IMAGE_MAX_BYTES = 1 * 1024 * 1024
PROFILE_IMAGE_MIME_TYPES = {
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/gif",
}


def normalize_image_url(raw_value, prefer_https=False):
    value = str(raw_value or "").strip()
    if not value:
        return ""
    if value.startswith("data:image/"):
        return value
    if value.startswith("//"):
        scheme = "https" if prefer_https else "http"
        value = f"{scheme}:{value}"
    if value.startswith("www."):
        scheme = "https" if prefer_https else "http"
        value = f"{scheme}://{value}"
    if prefer_https and value.startswith("http://"):
        value = "https://" + value[len("http://") :]
    if not (value.startswith("http://") or value.startswith("https://")):
        return ""
    host = urlparse(value).netloc.lower()
    if host in BLOCKED_IMAGE_HOSTS:
        return ""
    return value


def normalize_options(raw_options):
    if not isinstance(raw_options, list):
        return []
    cleaned = []
    for option in raw_options:
        text = str(option or "").strip()
        if text:
            cleaned.append(text)
    return cleaned


def normalize_question_type(raw_type, options):
    qtype = str(raw_type or "").strip().lower()
    if qtype == "true_false":
        return "true_false"
    if options and qtype not in {"multiple_choice", "text"}:
        return "multiple_choice"
    return qtype or ("multiple_choice" if options else "text")


def parse_questions(raw_questions, prefer_https=False):
    json_blob = extract_json_array(raw_questions)
    if not json_blob:
        return []

    try:
        data = json.loads(json_blob)
    except json.JSONDecodeError:
        return []

    items = []
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            question = str(item.get("question", "")).strip()
            answer = str(item.get("answer", "")).strip()
            image_url = normalize_image_url(item.get("image_url", ""), prefer_https)
            image_base64 = str(item.get("image_base64", "")).strip()
            image_mime = str(item.get("image_mime", "")).strip()
            if image_base64 and image_mime.startswith("image/"):
                image_url = f"data:{image_mime};base64,{image_base64}"
            options = normalize_options(item.get("options"))
            answer_index = item.get("answer_index")
            if options and isinstance(answer_index, int) and 0 <= answer_index < len(options):
                answer = options[answer_index]
            qtype = normalize_question_type(item.get("type"), options)
            if qtype == "true_false":
                options = ["Waar", "Onwaar"]
                if answer.lower() in {"true", "waar"}:
                    answer = "Waar"
                elif answer.lower() in {"false", "onwaar"}:
                    answer = "Onwaar"
            if question:
                items.append(
                    {
                        "question": question,
                        "answer": answer,
                        "image_url": image_url,
                        "options": options,
                        "type": qtype,
                    }
                )

    return items


def serialize_questions(items):
    payload = []
    for item in items:
        question = str(item.get("question", "")).strip()
        if not question:
            continue
        answer = str(item.get("answer", "")).strip()
        image_url = str(item.get("image_url", "")).strip()
        image_base64 = str(item.get("image_base64", "")).strip()
        image_mime = str(item.get("image_mime", "")).strip()
        qtype = str(item.get("type", "text")).strip().lower() or "text"
        options = normalize_options(item.get("options"))
        if qtype == "true_false":
            options = ["Waar", "Onwaar"]
        elif qtype != "multiple_choice" or not options:
            qtype = "text"
            options = []
        entry = {
            "question": question,
            "answer": answer,
            "image_url": image_url,
            "type": qtype,
            "options": options,
        }
        if image_base64 and image_mime.startswith("image/"):
            entry["image_base64"] = image_base64
            entry["image_mime"] = image_mime
        payload.append(entry)
    return json.dumps(payload, ensure_ascii=True)


def grade_answers_with_ai(items, user_answers):
    api_key = app.config.get("OPENROUTER_API_KEY")
    if not api_key:
        return None

    payload = []
    for idx, item in enumerate(items):
        question = item.get("question", "")
        correct_answer = item.get("answer", "")
        payload.append(
            {
                "index": idx,
                "question": question,
                "correct_answer": correct_answer,
                "student_answer": user_answers[idx] if idx < len(user_answers) else "",
            }
        )

    prompt = (
        "Je beoordeelt de quiz van een leerling. "
        "Bepaal per vraag of het antwoord correct is. "
        "Geef ALLEEN geldige JSON-array met objecten: "
        "{index: number, is_correct: boolean, feedback: string}. "
        "Feedback moet kort en behulpzaam zijn."
    )

    response = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://localhost:5000",
            "X-Title": "StudieQuiz",
        },
        json={
            "model": app.config["OPENROUTER_MODEL"],
            "messages": [
                {"role": "system", "content": "Je bent een strenge maar eerlijke beoordelaar."},
                {"role": "user", "content": prompt + "\n" + json.dumps(payload)},
            ],
            "temperature": 0.2,
        },
        timeout=60,
    )

    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        raise ValueError(
            f"OpenRouter request failed ({response.status_code}): {response.text}"
        ) from exc
    data = response.json()
    content = data["choices"][0]["message"]["content"].strip()
    json_blob = extract_json_array(content)
    if not json_blob:
        return None

    try:
        grading = json.loads(json_blob)
    except json.JSONDecodeError:
        return None

    if not isinstance(grading, list):
        return None

    return grading


def extract_text_from_pdf(file_storage):
    cleanup_uploads()
    filename = secure_filename(file_storage.filename or "document.pdf")
    unique_name = f"{uuid.uuid4().hex}_{filename}"
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)
    file_storage.save(file_path)

    reader = PdfReader(file_path)
    parts = []
    for page in reader.pages:
        text = page.extract_text() or ""
        parts.append(text)

    return "\n".join(parts).strip()


def ensure_quiz_subject_column():
    if not db.engine.url.drivername.startswith("sqlite"):
        return
    try:
        columns = db.session.execute(text("PRAGMA table_info(quiz)")).fetchall()
    except Exception:
        return

    column_names = {row[1] for row in columns}
    if not column_names:
        return
    if "subject" not in column_names:
        db.session.execute(text("ALTER TABLE quiz ADD COLUMN subject VARCHAR(120)"))
        db.session.commit()


def ensure_user_profile_columns():
    if not db.engine.url.drivername.startswith("sqlite"):
        return
    try:
        columns = db.session.execute(text("PRAGMA table_info(user)")).fetchall()
    except Exception:
        return

    column_names = {row[1] for row in columns}
    if not column_names:
        return
    if "nickname" not in column_names:
        db.session.execute(text("ALTER TABLE user ADD COLUMN nickname VARCHAR(120)"))
    if "profile_image_base64" not in column_names:
        db.session.execute(text("ALTER TABLE user ADD COLUMN profile_image_base64 TEXT"))
    if "profile_image_mime" not in column_names:
        db.session.execute(text("ALTER TABLE user ADD COLUMN profile_image_mime VARCHAR(120)"))
    db.session.commit()


_schema_checked = False


@app.before_request
def ensure_schema():
    global _schema_checked
    if _schema_checked:
        return
    db.create_all()
    ensure_quiz_subject_column()
    ensure_user_profile_columns()
    _schema_checked = True


def cleanup_uploads():
    upload_folder = app.config["UPLOAD_FOLDER"]
    retention = app.config.get("UPLOAD_RETENTION_SECONDS", 24 * 60 * 60)
    now = datetime.utcnow().timestamp()

    for name in os.listdir(upload_folder):
        path = os.path.join(upload_folder, name)
        if not os.path.isfile(path):
            continue
        try:
            modified = os.path.getmtime(path)
        except OSError:
            continue
        if now - modified > retention:
            try:
                os.remove(path)
            except OSError:
                continue


def clear_uploads_folder():
    upload_folder = app.config["UPLOAD_FOLDER"]
    for name in os.listdir(upload_folder):
        path = os.path.join(upload_folder, name)
        if not os.path.isfile(path):
            continue
        try:
            os.remove(path)
        except OSError:
            continue


def update_env_value(key, value):
    env_path = os.path.join(app.config["BASE_DIR"], ".env")
    try:
        with open(env_path, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except FileNotFoundError:
        lines = []

    updated = False
    new_lines = []
    for line in lines:
        if not line or line.lstrip().startswith("#") or "=" not in line:
            new_lines.append(line)
            continue
        existing_key, _ = line.split("=", 1)
        if existing_key.strip() == key:
            new_lines.append(f"{key}={value}")
            updated = True
        else:
            new_lines.append(line)

    if not updated:
        new_lines.append(f"{key}={value}")

    with open(env_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(new_lines).rstrip() + "\n")


def read_env_text():
    env_path = os.path.join(app.config["BASE_DIR"], ".env")
    try:
        with open(env_path, "r", encoding="utf-8") as handle:
            return handle.read()
    except FileNotFoundError:
        return ""


def parse_env_text(raw_text):
    values = {}
    for line in raw_text.splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        values[key] = value.strip()
    return values


def require_admin(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return view_func(*args, **kwargs)

    return wrapped


@app.route("/teacher")
@login_required
def teacher_dashboard():
    if not require_teacher():
        return redirect(url_for("student_dashboard"))
    quizzes = Quiz.query.filter_by(teacher_id=current_user.id).order_by(Quiz.created_at.desc()).all()
    classes = Classroom.query.filter_by(teacher_id=current_user.id).order_by(Classroom.created_at.desc()).all()
    return render_template("teacher_dashboard.html", quizzes=quizzes, classes=classes)


def generate_class_code():
    return uuid.uuid4().hex[:8].upper()


@app.route("/teacher/classes/new", methods=["POST"])
@login_required
def create_class():
    if not require_teacher():
        return redirect(url_for("student_dashboard"))

    name = request.form.get("class_name", "").strip()
    if not name:
        flash("Geef een klassenaam op.", "error")
        return redirect(url_for("teacher_dashboard"))

    code = generate_class_code()
    while Classroom.query.filter_by(code=code).first() is not None:
        code = generate_class_code()

    classroom = Classroom(name=name, code=code, teacher_id=current_user.id)
    db.session.add(classroom)
    db.session.commit()
    flash("Klas aangemaakt.", "success")
    return redirect(url_for("teacher_dashboard"))


@app.route("/teacher/classes/<int:class_id>")
@login_required
def class_detail(class_id):
    if not require_teacher():
        return redirect(url_for("student_dashboard"))

    classroom = Classroom.query.filter_by(id=class_id, teacher_id=current_user.id).first_or_404()
    enrollments = Enrollment.query.filter_by(class_id=classroom.id).all()
    students = [enrollment.student for enrollment in enrollments]
    quizzes = Quiz.query.filter_by(teacher_id=current_user.id).order_by(Quiz.created_at.desc()).all()
    classes = Classroom.query.filter_by(teacher_id=current_user.id).order_by(Classroom.created_at.desc()).all()
    return render_template(
        "teacher_dashboard.html",
        quizzes=quizzes,
        classes=classes,
        classroom=classroom,
        students=students,
    )


@app.route("/teacher/classes/<int:class_id>/delete", methods=["POST"])
@login_required
def delete_class(class_id):
    if not require_teacher():
        return redirect(url_for("student_dashboard"))

    classroom = Classroom.query.filter_by(id=class_id, teacher_id=current_user.id).first_or_404()

    Enrollment.query.filter_by(class_id=classroom.id).delete()
    quizzes = Quiz.query.filter_by(class_id=classroom.id, teacher_id=current_user.id).all()
    for quiz in quizzes:
        quiz.class_id = None

    db.session.delete(classroom)
    db.session.commit()
    flash("Klas verwijderd.", "success")
    return redirect(url_for("teacher_dashboard"))


@app.route("/teacher/quizzes/new", methods=["GET", "POST"])
@login_required
def create_quiz():
    if not require_teacher():
        return redirect(url_for("student_dashboard"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        subject = request.form.get("subject", "").strip()
        selected_chapters, chapter_manual = parse_chapter_selection(request.form)
        question_count = parse_question_count(request.form)
        chapter = ", ".join(selected_chapters)
        source_text = request.form.get("source_text", "").strip()
        source_file = request.files.get("source_pdf")
        questions = request.form.get("questions", "").strip()
        class_id = request.form.get("class_id")
        action = request.form.get("action", "save")
        publish_now = request.form.get("publish_now") == "on"
        selected_class_id = int(class_id) if class_id and class_id.isdigit() else None

        if source_file and source_file.filename:
            if source_file.mimetype != "application/pdf":
                flash("Upload een PDF-bestand.", "error")
                classes = Classroom.query.filter_by(teacher_id=current_user.id).order_by(Classroom.created_at.desc()).all()
                return render_template(
                    "create_quiz.html",
                    action_url=url_for("create_quiz"),
                    submit_label="Quiz opslaan",
                    classes=classes,
                    selected_class_id=selected_class_id,
                    title=title,
                    subject=subject,
                    chapter_selected=selected_chapters,
                    chapter_manual=chapter_manual,
                    question_count=question_count,
                    source_text=source_text,
                    questions=questions,
                    show_questions=bool(questions),
                    headings=extract_chapter_headings(source_text),
                    published=publish_now,
                )

            source_text = extract_text_from_pdf(source_file)

        if action == "extract":
            return render_template(
                "create_quiz.html",
                action_url=url_for("create_quiz"),
                submit_label="Quiz opslaan",
                classes=Classroom.query.filter_by(teacher_id=current_user.id).order_by(Classroom.created_at.desc()).all(),
                selected_class_id=selected_class_id,
                title=title,
                subject=subject,
                chapter_selected=selected_chapters,
                chapter_manual=chapter_manual,
                question_count=question_count,
                source_text=source_text,
                questions=questions,
                show_questions=bool(questions),
                headings=extract_chapter_headings(source_text),
                published=publish_now,
            )

        if action == "generate":
            if not selected_chapters or not source_text:
                flash("Hoofdstuk en brontekst zijn nodig om vragen te genereren.", "error")
            else:
                try:
                    chapter_text = extract_chapters_text(source_text, selected_chapters)
                    if not chapter_text:
                        flash("Hoofdstuk niet gevonden. Gebruik de exacte titel.", "error")
                        return render_template(
                            "create_quiz.html",
                            action_url=url_for("create_quiz"),
                            submit_label="Quiz opslaan",
                            classes=Classroom.query.filter_by(teacher_id=current_user.id).order_by(Classroom.created_at.desc()).all(),
                            selected_class_id=selected_class_id,
                            title=title,
                            subject=subject,
                            chapter_selected=selected_chapters,
                            chapter_manual=chapter_manual,
                            question_count=question_count,
                            source_text=source_text,
                            questions=questions,
                            show_questions=False,
                            headings=extract_chapter_headings(source_text),
                            published=publish_now,
                        )
                    questions = generate_questions_from_text(chapter_text, chapter, subject, question_count)
                    flash("Vragen gegenereerd. Controleer en sla op wanneer je klaar bent.", "success")
                except Exception as exc:
                    flash(f"Vragen genereren mislukt: {exc}", "error")

            return render_template(
                "create_quiz.html",
                action_url=url_for("create_quiz"),
                submit_label="Quiz opslaan",
                classes=Classroom.query.filter_by(teacher_id=current_user.id).order_by(Classroom.created_at.desc()).all(),
                selected_class_id=selected_class_id,
                title=title,
                subject=subject,
                chapter_selected=selected_chapters,
                chapter_manual=chapter_manual,
                question_count=question_count,
                source_text=source_text,
                questions=questions,
                show_questions=bool(questions),
                headings=extract_chapter_headings(source_text),
                published=publish_now,
            )

        if not title or not source_text:
            flash("Titel en brontekst zijn verplicht.", "error")
            return render_template(
                "create_quiz.html",
                action_url=url_for("create_quiz"),
                submit_label="Quiz opslaan",
                classes=Classroom.query.filter_by(teacher_id=current_user.id).order_by(Classroom.created_at.desc()).all(),
                selected_class_id=selected_class_id,
                title=title,
                subject=subject,
                chapter_selected=selected_chapters,
                chapter_manual=chapter_manual,
                question_count=question_count,
                source_text=source_text,
                questions=questions,
                show_questions=bool(questions),
                headings=extract_chapter_headings(source_text),
                published=publish_now,
            )

        if not subject:
            flash("Vak is verplicht.", "error")
            return render_template(
                "create_quiz.html",
                action_url=url_for("create_quiz"),
                submit_label="Quiz opslaan",
                classes=Classroom.query.filter_by(teacher_id=current_user.id).order_by(Classroom.created_at.desc()).all(),
                selected_class_id=selected_class_id,
                title=title,
                subject=subject,
                chapter_selected=selected_chapters,
                chapter_manual=chapter_manual,
                question_count=question_count,
                source_text=source_text,
                questions=questions,
                show_questions=bool(questions),
                headings=extract_chapter_headings(source_text),
                published=publish_now,
            )

        if not class_id:
            flash("Kies een klas.", "error")
            return redirect(url_for("create_quiz"))

        if not questions and not selected_chapters:
            flash("Voer vragen in of kies een hoofdstuk om te genereren.", "error")
            return render_template(
                "create_quiz.html",
                action_url=url_for("create_quiz"),
                submit_label="Quiz opslaan",
                classes=Classroom.query.filter_by(teacher_id=current_user.id).order_by(Classroom.created_at.desc()).all(),
                selected_class_id=selected_class_id,
                title=title,
                subject=subject,
                chapter_selected=selected_chapters,
                chapter_manual=chapter_manual,
                question_count=question_count,
                source_text=source_text,
                questions="",
                show_questions=False,
                headings=extract_chapter_headings(source_text),
                published=publish_now,
            )

        if not questions:
            try:
                chapter_text = extract_chapters_text(source_text, selected_chapters)
                if not chapter_text:
                    flash("Hoofdstuk niet gevonden. Gebruik de exacte titel.", "error")
                    return render_template(
                        "create_quiz.html",
                        action_url=url_for("create_quiz"),
                        submit_label="Quiz opslaan",
                        classes=Classroom.query.filter_by(teacher_id=current_user.id).order_by(Classroom.created_at.desc()).all(),
                        selected_class_id=selected_class_id,
                        title=title,
                        subject=subject,
                        chapter_selected=selected_chapters,
                        chapter_manual=chapter_manual,
                        question_count=question_count,
                        source_text=source_text,
                        questions="",
                        show_questions=False,
                        headings=extract_chapter_headings(source_text),
                        published=publish_now,
                    )
                questions = generate_questions_from_text(chapter_text, chapter, subject, question_count)
                flash("Vragen automatisch gegenereerd.", "success")
            except Exception as exc:
                flash(f"Vragen genereren mislukt: {exc}", "error")
                return render_template(
                    "create_quiz.html",
                    action_url=url_for("create_quiz"),
                    submit_label="Quiz opslaan",
                    classes=Classroom.query.filter_by(teacher_id=current_user.id).order_by(Classroom.created_at.desc()).all(),
                    selected_class_id=selected_class_id,
                    title=title,
                    subject=subject,
                    chapter_selected=selected_chapters,
                    chapter_manual=chapter_manual,
                    question_count=question_count,
                    source_text=source_text,
                    questions="",
                    show_questions=False,
                    headings=extract_chapter_headings(source_text),
                    published=publish_now,
                )

        quiz = Quiz(
            title=title,
            subject=subject,
            chapter=chapter,
            source_text=source_text,
            questions=questions,
            published=publish_now,
            teacher_id=current_user.id,
            class_id=int(class_id),
        )
        db.session.add(quiz)
        db.session.commit()
        flash("Quiz aangemaakt.", "success")
        return redirect(url_for("teacher_dashboard"))

    classes = Classroom.query.filter_by(teacher_id=current_user.id).order_by(Classroom.created_at.desc()).all()
    return render_template(
        "create_quiz.html",
        action_url=url_for("create_quiz"),
        submit_label="Quiz opslaan",
        classes=classes,
        title="",
        subject="",
        chapter_selected=[],
        chapter_manual="",
        question_count=8,
        source_text="",
        questions="",
        show_questions=False,
        headings=[],
        published=False,
    )


TEACHER_HELP_SYSTEM_MESSAGE = (
    "Je bent de help-assistent voor docenten in StudieQuiz. "
    "Antwoord in het Nederlands, kort en concreet. "
    "Gebruik alleen de info hieronder. Als iets onbekend is, zeg dat.\n"
    "\nDocentendashboard:\n"
    "- Nieuwe quiz maken: maakt een quiz vanuit brontekst/PDF, met hoofdstukken en AI vragen.\n"
    "- Nieuwe quiz (editor): start direct in de quiz editor om vragen handmatig te maken.\n"
    "- Klassen: klas aanmaken, klascode bekijken, leerlingen bekijken, klas verwijderen.\n"
    "- Jouw quizzen: bewerken, vragen bewerken, resultaten bekijken, publiceren, verwijderen.\n"
    "\nQuiz editor:\n"
    "- Links staat het menu met vraagtypes; sleep een tegel naar het canvas om een vraag toe te voegen.\n"
    "- Je kunt vragen verslepen om de volgorde te wijzigen.\n"
    "- Open vraag: vrij antwoordveld.\n"
    "- Meerkeuze: voeg opties toe en kies het juiste antwoord in de dropdown.\n"
    "- Waar/Onwaar: vaste opties, kies het juiste antwoord.\n"
    "- Afbeelding: upload een afbeelding per vraag, preview verschijnt; verwijder via de knop.\n"
    "- Opslaan: slaat alle vragen op voor de quiz.\n"
    "\nQuiz aanmaken via editor:\n"
    "- Vul titel, vak, hoofdstuk en klas in. Brontekst is optioneel.\n"
    "- Na opslaan kom je terug in de editor om verder te bewerken.\n"
)


@app.route("/teacher/help/chat", methods=["POST"])
@login_required
def teacher_help_chat():
    if not require_teacher():
        return jsonify({"error": "Alleen docenten hebben toegang."}), 403

    api_key = app.config.get("OPENROUTER_API_KEY")
    if not api_key:
        return jsonify({"error": "OpenRouter API-sleutel ontbreekt."}), 400

    payload = request.get_json(silent=True) or {}
    message = str(payload.get("message", "")).strip()
    if not message:
        return jsonify({"error": "Stel een vraag."}), 400
    if len(message) > 2000:
        return jsonify({"error": "Vraag is te lang."}), 400

    model = app.config.get("OPENROUTER_HELP_MODEL") or app.config.get("OPENROUTER_MODEL")
    try:
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "http://localhost:5000",
                "X-Title": "StudieQuiz",
            },
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": TEACHER_HELP_SYSTEM_MESSAGE},
                    {"role": "user", "content": message},
                ],
                "temperature": 0.2,
            },
            timeout=45,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        status = getattr(exc.response, "status_code", 500)
        return (
            jsonify({"error": f"OpenRouter request failed ({status})."}),
            500,
        )

    try:
        data = response.json()
    except ValueError:
        return jsonify({"error": "Onverwachte AI response."}), 500

    content = str(
        data.get("choices", [{}])[0].get("message", {}).get("content", "")
    ).strip()
    if not content:
        return jsonify({"error": "Geen antwoord ontvangen."}), 500
    return jsonify({"answer": content})


@app.route("/teacher/help/chat/stream", methods=["POST"])
@login_required
def teacher_help_chat_stream():
    if not require_teacher():
        return jsonify({"error": "Alleen docenten hebben toegang."}), 403

    api_key = app.config.get("OPENROUTER_API_KEY")
    if not api_key:
        return jsonify({"error": "OpenRouter API-sleutel ontbreekt."}), 400

    payload = request.get_json(silent=True) or {}
    message = str(payload.get("message", "")).strip()
    if not message:
        return jsonify({"error": "Stel een vraag."}), 400
    if len(message) > 2000:
        return jsonify({"error": "Vraag is te lang."}), 400

    model = app.config.get("OPENROUTER_HELP_MODEL") or app.config.get("OPENROUTER_MODEL")

    def stream_response():
        try:
            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "http://localhost:5000",
                    "X-Title": "StudieQuiz",
                },
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": TEACHER_HELP_SYSTEM_MESSAGE},
                        {"role": "user", "content": message},
                    ],
                    "temperature": 0.2,
                    "stream": True,
                },
                timeout=60,
                stream=True,
            )
            response.raise_for_status()
        except requests.RequestException:
            yield "[ERROR]"
            return

        for line in response.iter_lines(decode_unicode=True):
            if not line:
                continue
            if not line.startswith("data:"):
                continue
            data = line.split("data:", 1)[1].strip()
            if data == "[DONE]":
                break
            try:
                chunk = json.loads(data)
            except json.JSONDecodeError:
                continue
            delta = (
                chunk.get("choices", [{}])[0]
                .get("delta", {})
                .get("content", "")
            )
            if delta:
                yield delta

    return Response(stream_with_context(stream_response()), mimetype="text/plain")


@app.route("/help/chat", methods=["POST"])
@login_required
def teacher_help_chat_stream_alias():
    return teacher_help_chat_stream()


@app.route("/teacher/quizzes/new/editor", methods=["GET", "POST"])
@login_required
def create_quiz_editor():
    if not require_teacher():
        return redirect(url_for("student_dashboard"))

    classes = (
        Classroom.query.filter_by(teacher_id=current_user.id)
        .order_by(Classroom.created_at.desc())
        .all()
    )

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        subject = request.form.get("subject", "").strip()
        chapter = request.form.get("chapter", "").strip()
        source_text = request.form.get("source_text", "").strip()
        class_id = request.form.get("class_id", "")
        raw_questions = request.form.get("questions_json", "").strip()
        items = parse_questions(raw_questions, prefer_https=request.is_secure)
        selected_class_id = int(class_id) if class_id and class_id.isdigit() else None

        has_error = False
        if not title:
            flash("Titel is verplicht.", "error")
            has_error = True
        if not subject:
            flash("Vak is verplicht.", "error")
            has_error = True
        if not chapter:
            flash("Hoofdstuk is verplicht.", "error")
            has_error = True
        if not selected_class_id:
            flash("Kies een klas.", "error")
            has_error = True
        if not items:
            flash("Voeg minimaal 1 geldige vraag toe.", "error")
            has_error = True

        if has_error:
            return render_template(
                "quiz_editor.html",
                action_url=url_for("create_quiz_editor"),
                create_mode=True,
                classes=classes,
                selected_class_id=selected_class_id,
                title=title,
                subject=subject,
                chapter=chapter,
                source_text=source_text,
                items=items,
            )

        if not source_text:
            source_text = "Handmatig aangemaakt in de editor."

        quiz = Quiz(
            title=title,
            subject=subject,
            chapter=chapter,
            source_text=source_text,
            questions=serialize_questions(items),
            published=False,
            teacher_id=current_user.id,
            class_id=selected_class_id,
        )
        db.session.add(quiz)
        db.session.commit()
        flash("Quiz aangemaakt.", "success")
        return redirect(url_for("edit_quiz_questions", quiz_id=quiz.id))

    return render_template(
        "quiz_editor.html",
        action_url=url_for("create_quiz_editor"),
        create_mode=True,
        classes=classes,
        selected_class_id=None,
        title="",
        subject="",
        chapter="",
        source_text="",
        items=[],
    )


@app.route("/teacher/quizzes/<int:quiz_id>/edit", methods=["GET", "POST"])
@login_required
def edit_quiz(quiz_id):
    if not require_teacher():
        return redirect(url_for("student_dashboard"))

    quiz = Quiz.query.filter_by(id=quiz_id, teacher_id=current_user.id).first_or_404()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        subject = request.form.get("subject", "").strip()
        selected_chapters, chapter_manual = parse_chapter_selection(request.form)
        question_count = parse_question_count(request.form)
        chapter = ", ".join(selected_chapters)
        source_text = request.form.get("source_text", "").strip()
        questions = request.form.get("questions", "").strip()
        action = request.form.get("action", "save")
        publish_now = request.form.get("publish_now") == "on"
        class_id = request.form.get("class_id")
        source_file = request.files.get("source_pdf")
        selected_class_id = int(class_id) if class_id and class_id.isdigit() else quiz.class_id

        if source_file and source_file.filename:
            if source_file.mimetype != "application/pdf":
                flash("Upload een PDF-bestand.", "error")
                classes = Classroom.query.filter_by(teacher_id=current_user.id).order_by(Classroom.created_at.desc()).all()
                return render_template(
                    "create_quiz.html",
                    action_url=url_for("edit_quiz", quiz_id=quiz.id),
                    submit_label="Quiz bijwerken",
                    classes=classes,
                    selected_class_id=selected_class_id,
                    title=title,
                    subject=subject,
                    chapter_selected=selected_chapters,
                    chapter_manual=chapter_manual,
                    question_count=question_count,
                    source_text=source_text,
                    questions=questions,
                    show_questions=bool(questions),
                    headings=extract_chapter_headings(source_text),
                    published=publish_now,
                )

            source_text = extract_text_from_pdf(source_file)

        if action == "extract":
            return render_template(
                "create_quiz.html",
                action_url=url_for("edit_quiz", quiz_id=quiz.id),
                submit_label="Quiz bijwerken",
                classes=Classroom.query.filter_by(teacher_id=current_user.id).order_by(Classroom.created_at.desc()).all(),
                selected_class_id=selected_class_id,
                title=title,
                subject=subject,
                chapter_selected=selected_chapters,
                chapter_manual=chapter_manual,
                question_count=question_count,
                source_text=source_text,
                questions=questions,
                show_questions=bool(questions),
                headings=extract_chapter_headings(source_text),
                published=publish_now,
            )

        if action == "generate":
            if not selected_chapters or not source_text:
                flash("Hoofdstuk en brontekst zijn nodig om vragen te genereren.", "error")
            else:
                try:
                    chapter_text = extract_chapters_text(source_text, selected_chapters)
                    if not chapter_text:
                        flash("Hoofdstuk niet gevonden. Gebruik de exacte titel.", "error")
                        return render_template(
                            "create_quiz.html",
                            action_url=url_for("edit_quiz", quiz_id=quiz.id),
                            submit_label="Quiz bijwerken",
                            classes=Classroom.query.filter_by(teacher_id=current_user.id).order_by(Classroom.created_at.desc()).all(),
                            selected_class_id=selected_class_id,
                            title=title,
                            subject=subject,
                            chapter_selected=selected_chapters,
                            chapter_manual=chapter_manual,
                            question_count=question_count,
                            source_text=source_text,
                            questions=questions,
                            show_questions=False,
                            headings=extract_chapter_headings(source_text),
                            published=publish_now,
                        )
                    questions = generate_questions_from_text(chapter_text, chapter, subject, question_count)
                    flash("Vragen gegenereerd. Controleer en sla op wanneer je klaar bent.", "success")
                except Exception as exc:
                    flash(f"Vragen genereren mislukt: {exc}", "error")

            return render_template(
                "create_quiz.html",
                action_url=url_for("edit_quiz", quiz_id=quiz.id),
                submit_label="Quiz bijwerken",
                classes=Classroom.query.filter_by(teacher_id=current_user.id).order_by(Classroom.created_at.desc()).all(),
                selected_class_id=selected_class_id,
                title=title,
                subject=subject,
                chapter_selected=selected_chapters,
                chapter_manual=chapter_manual,
                question_count=question_count,
                source_text=source_text,
                questions=questions,
                show_questions=bool(questions),
                headings=extract_chapter_headings(source_text),
                published=publish_now,
            )

        if not title or not source_text:
            flash("Titel en brontekst zijn verplicht.", "error")
            return render_template(
                "create_quiz.html",
                action_url=url_for("edit_quiz", quiz_id=quiz.id),
                submit_label="Quiz bijwerken",
                classes=Classroom.query.filter_by(teacher_id=current_user.id).order_by(Classroom.created_at.desc()).all(),
                selected_class_id=selected_class_id,
                title=title,
                subject=subject,
                chapter_selected=selected_chapters,
                chapter_manual=chapter_manual,
                question_count=question_count,
                source_text=source_text,
                questions=questions,
                show_questions=bool(questions),
                headings=extract_chapter_headings(source_text),
                published=publish_now,
            )

        if not subject:
            flash("Vak is verplicht.", "error")
            return render_template(
                "create_quiz.html",
                action_url=url_for("edit_quiz", quiz_id=quiz.id),
                submit_label="Quiz bijwerken",
                classes=Classroom.query.filter_by(teacher_id=current_user.id).order_by(Classroom.created_at.desc()).all(),
                selected_class_id=selected_class_id,
                title=title,
                subject=subject,
                chapter_selected=selected_chapters,
                chapter_manual=chapter_manual,
                question_count=question_count,
                source_text=source_text,
                questions=questions,
                show_questions=bool(questions),
                headings=extract_chapter_headings(source_text),
                published=publish_now,
            )

        if not class_id:
            flash("Kies een klas.", "error")
            return redirect(url_for("edit_quiz", quiz_id=quiz.id))

        if not questions and not selected_chapters:
            flash("Voer vragen in of kies een hoofdstuk om te genereren.", "error")
            return render_template(
                "create_quiz.html",
                action_url=url_for("edit_quiz", quiz_id=quiz.id),
                submit_label="Quiz bijwerken",
                classes=Classroom.query.filter_by(teacher_id=current_user.id).order_by(Classroom.created_at.desc()).all(),
                selected_class_id=selected_class_id,
                title=title,
                subject=subject,
                chapter_selected=selected_chapters,
                chapter_manual=chapter_manual,
                question_count=question_count,
                source_text=source_text,
                questions="",
                show_questions=False,
                headings=extract_chapter_headings(source_text),
                published=publish_now,
            )

        if not questions:
            try:
                chapter_text = extract_chapters_text(source_text, selected_chapters)
                if not chapter_text:
                    flash("Hoofdstuk niet gevonden. Gebruik de exacte titel.", "error")
                    return render_template(
                        "create_quiz.html",
                        action_url=url_for("edit_quiz", quiz_id=quiz.id),
                        submit_label="Quiz bijwerken",
                        classes=Classroom.query.filter_by(teacher_id=current_user.id).order_by(Classroom.created_at.desc()).all(),
                        selected_class_id=selected_class_id,
                        title=title,
                        subject=subject,
                        chapter_selected=selected_chapters,
                        chapter_manual=chapter_manual,
                        question_count=question_count,
                        source_text=source_text,
                        questions="",
                        show_questions=False,
                        headings=extract_chapter_headings(source_text),
                        published=publish_now,
                    )
                questions = generate_questions_from_text(chapter_text, chapter, subject, question_count)
                flash("Vragen automatisch gegenereerd.", "success")
            except Exception as exc:
                flash(f"Vragen genereren mislukt: {exc}", "error")
                return render_template(
                    "create_quiz.html",
                    action_url=url_for("edit_quiz", quiz_id=quiz.id),
                    submit_label="Quiz bijwerken",
                    classes=Classroom.query.filter_by(teacher_id=current_user.id).order_by(Classroom.created_at.desc()).all(),
                    selected_class_id=selected_class_id,
                    title=title,
                    subject=subject,
                    chapter_selected=selected_chapters,
                    chapter_manual=chapter_manual,
                    question_count=question_count,
                    source_text=source_text,
                    questions="",
                    show_questions=False,
                    headings=extract_chapter_headings(source_text),
                    published=publish_now,
                )

        quiz.title = title
        quiz.subject = subject
        quiz.chapter = chapter
        quiz.source_text = source_text
        quiz.questions = questions
        quiz.published = publish_now
        quiz.class_id = int(class_id)
        db.session.commit()
        flash("Quiz bijgewerkt.", "success")
        return redirect(url_for("teacher_dashboard"))

    classes = Classroom.query.filter_by(teacher_id=current_user.id).order_by(Classroom.created_at.desc()).all()
    headings = extract_chapter_headings(quiz.source_text)
    existing_chapters = [item.strip() for item in quiz.chapter.split(",") if item.strip()]
    chapter_selected = [item for item in existing_chapters if item in headings]
    chapter_manual = ", ".join([item for item in existing_chapters if item not in headings])
    return render_template(
        "create_quiz.html",
        action_url=url_for("edit_quiz", quiz_id=quiz.id),
        submit_label="Quiz bijwerken",
        classes=classes,
        selected_class_id=quiz.class_id,
        title=quiz.title,
        subject=quiz.subject or "",
        chapter_selected=chapter_selected,
        chapter_manual=chapter_manual,
        question_count=8,
        source_text=quiz.source_text,
        questions=quiz.questions,
        show_questions=bool(quiz.questions),
        headings=headings,
        published=quiz.published,
    )


@app.route("/teacher/quizzes/<int:quiz_id>/questions", methods=["GET", "POST"])
@login_required
def edit_quiz_questions(quiz_id):
    if not require_teacher():
        return redirect(url_for("student_dashboard"))

    quiz = Quiz.query.filter_by(id=quiz_id, teacher_id=current_user.id).first_or_404()

    if request.method == "POST":
        raw_questions = request.form.get("questions_json", "").strip()
        items = parse_questions(raw_questions, prefer_https=request.is_secure)
        if not items:
            flash("Voeg minimaal 1 geldige vraag toe.", "error")
            return render_template(
                "quiz_editor.html",
                action_url=url_for("edit_quiz_questions", quiz_id=quiz.id),
                create_mode=False,
                quiz=quiz,
                items=items,
            )

        quiz.questions = serialize_questions(items)
        db.session.commit()
        flash("Vragen bijgewerkt.", "success")
        return redirect(url_for("edit_quiz_questions", quiz_id=quiz.id))

    items = parse_questions(quiz.questions, prefer_https=request.is_secure)
    return render_template(
        "quiz_editor.html",
        action_url=url_for("edit_quiz_questions", quiz_id=quiz.id),
        create_mode=False,
        quiz=quiz,
        items=items,
    )


@app.route("/teacher/quizzes/<int:quiz_id>/delete", methods=["POST"])
@login_required
def delete_quiz(quiz_id):
    if not require_teacher():
        return redirect(url_for("student_dashboard"))

    quiz = Quiz.query.filter_by(id=quiz_id, teacher_id=current_user.id).first_or_404()
    QuizAttempt.query.filter_by(quiz_id=quiz.id).delete()
    db.session.delete(quiz)
    db.session.commit()
    flash("Quiz verwijderd.", "success")
    return redirect(url_for("teacher_dashboard"))


@app.route("/teacher/quizzes/<int:quiz_id>/publish", methods=["POST"])
@login_required
def publish_quiz(quiz_id):
    if not require_teacher():
        return redirect(url_for("student_dashboard"))
    quiz = Quiz.query.filter_by(id=quiz_id, teacher_id=current_user.id).first_or_404()
    quiz.published = True
    db.session.commit()
    flash("Quiz gepubliceerd.", "success")
    return redirect(url_for("teacher_dashboard"))


@app.route("/teacher/quizzes/<int:quiz_id>/results")
@login_required
def quiz_results(quiz_id):
    if not require_teacher():
        return redirect(url_for("student_dashboard"))

    quiz = Quiz.query.filter_by(id=quiz_id, teacher_id=current_user.id).first_or_404()
    attempts = (
        QuizAttempt.query.filter_by(quiz_id=quiz.id)
        .order_by(QuizAttempt.created_at.desc())
        .all()
    )

    attempt_rows = []
    question_stats = {}
    total_correct = 0
    total_questions = 0

    for attempt in attempts:
        try:
            items = json.loads(attempt.results_json or "[]")
        except json.JSONDecodeError:
            items = []

        wrong_items = []
        for item in items:
            if not isinstance(item, dict):
                continue
            question = str(item.get("question", "")).strip()
            correct = str(item.get("correct", "")).strip()
            user = str(item.get("user", "")).strip()
            is_correct = bool(item.get("is_correct"))

            if question:
                stats = question_stats.setdefault(
                    question,
                    {"total": 0, "wrong": 0, "wrong_answers": {}},
                )
                stats["total"] += 1
                if not is_correct:
                    stats["wrong"] += 1
                    wrong_answer = user or "(leeg)"
                    stats["wrong_answers"][wrong_answer] = (
                        stats["wrong_answers"].get(wrong_answer, 0) + 1
                    )
                    wrong_items.append(
                        {
                            "question": question,
                            "user": user or "(leeg)",
                            "correct": correct,
                        }
                    )

        total_correct += attempt.score_correct
        total_questions += attempt.score_total

        attempt_rows.append(
            {
                "student_name": attempt.student.name,
                "student_email": attempt.student.email,
                "score_correct": attempt.score_correct,
                "score_total": attempt.score_total,
                "created_at": attempt.created_at,
                "wrong_items": wrong_items,
            }
        )

    question_summaries = []
    for question, stats in question_stats.items():
        total = stats["total"]
        wrong = stats["wrong"]
        wrong_rate = round((wrong / total) * 100) if total else 0
        top_wrong = sorted(
            stats["wrong_answers"].items(), key=lambda item: item[1], reverse=True
        )[:3]
        question_summaries.append(
            {
                "question": question,
                "wrong": wrong,
                "total": total,
                "wrong_rate": wrong_rate,
                "top_wrong": top_wrong,
            }
        )

    question_summaries.sort(key=lambda item: item["wrong"], reverse=True)
    average_score = round((total_correct / total_questions) * 100) if total_questions else 0

    return render_template(
        "quiz_results.html",
        quiz=quiz,
        attempts=attempt_rows,
        question_summaries=question_summaries,
        average_score=average_score,
    )


@app.route("/student")
@login_required
def student_dashboard():
    if current_user.role != "student":
        return redirect(url_for("teacher_dashboard"))
    class_ids = [enrollment.class_id for enrollment in current_user.enrollments]
    quizzes = []
    classes = []
    if class_ids:
        quizzes = Quiz.query.filter(Quiz.published == True, Quiz.class_id.in_(class_ids)).order_by(Quiz.created_at.desc()).all()
        classes = Classroom.query.filter(Classroom.id.in_(class_ids)).all()
    return render_template("student_dashboard.html", quizzes=quizzes, classes=classes)


@app.route("/student/settings", methods=["GET", "POST"])
@login_required
def student_settings():
    if current_user.role != "student":
        flash("Alleen leerlingen kunnen instellingen aanpassen.", "error")
        return redirect(url_for("teacher_dashboard"))

    if request.method == "POST":
        nickname = request.form.get("nickname", "").strip()
        current_user.nickname = nickname or None

        profile_file = request.files.get("profile_image")
        if profile_file and profile_file.filename:
            if profile_file.mimetype not in PROFILE_IMAGE_MIME_TYPES:
                flash("Upload een geldige afbeelding (png, jpg, webp, gif).", "error")
                return render_template("student_settings.html", student=current_user)

            image_bytes = profile_file.read()
            if len(image_bytes) > PROFILE_IMAGE_MAX_BYTES:
                flash("Afbeelding is te groot (max 1 MB).", "error")
                return render_template("student_settings.html", student=current_user)

            current_user.profile_image_base64 = base64.b64encode(image_bytes).decode("ascii")
            current_user.profile_image_mime = profile_file.mimetype

        db.session.commit()
        flash("Instellingen opgeslagen.", "success")
        return redirect(url_for("student_settings"))

    return render_template("student_settings.html", student=current_user)


@app.route("/student/join", methods=["POST"])
@login_required
def join_class():
    if current_user.role != "student":
        flash("Alleen leerlingen kunnen deelnemen aan een klas.", "error")
        return redirect(url_for("teacher_dashboard"))
    code = request.form.get("class_code", "").strip().upper()
    if not code:
        flash("Voer een klascode in.", "error")
        return redirect(url_for("student_dashboard"))

    classroom = Classroom.query.filter_by(code=code).first()
    if classroom is None:
        flash("Klascode niet gevonden.", "error")
        return redirect(url_for("student_dashboard"))

    existing = Enrollment.query.filter_by(student_id=current_user.id, class_id=classroom.id).first()
    if existing:
        flash("Je zit al in deze klas.", "success")
        return redirect(url_for("student_dashboard"))

    enrollment = Enrollment(student_id=current_user.id, class_id=classroom.id)
    db.session.add(enrollment)
    db.session.commit()
    flash("Je bent toegevoegd aan de klas.", "success")
    return redirect(url_for("student_dashboard"))


@app.route("/quizzes/<int:quiz_id>", methods=["GET", "POST"])
@login_required
def quiz_detail(quiz_id):
    quiz = Quiz.query.filter_by(id=quiz_id, published=True).first_or_404()
    if current_user.role == "student":
        class_ids = [enrollment.class_id for enrollment in current_user.enrollments]
        if quiz.class_id not in class_ids:
            flash("Je hebt geen toegang tot deze quiz.", "error")
            return redirect(url_for("student_dashboard"))
    items = parse_questions(quiz.questions, prefer_https=request.is_secure)
    results = None

    if request.method == "POST":
        graded = []
        correct_count = 0
        user_answers = []
        for idx, _ in enumerate(items):
            user_answers.append(request.form.get(f"answer_{idx}", "").strip())

        ai_grades = grade_answers_with_ai(items, user_answers)
        ai_lookup = {}
        if ai_grades:
            for item in ai_grades:
                if not isinstance(item, dict):
                    continue
                index = item.get("index")
                if isinstance(index, int):
                    ai_lookup[index] = item

        for idx, item in enumerate(items):
            question = item.get("question", "")
            correct_answer = item.get("answer", "")
            image_url = item.get("image_url", "")
            user_answer = user_answers[idx] if idx < len(user_answers) else ""
            ai_item = ai_lookup.get(idx)
            if ai_item is not None:
                is_correct = bool(ai_item.get("is_correct"))
                feedback = str(ai_item.get("feedback", "")).strip()
            else:
                is_correct = bool(correct_answer) and user_answer.lower() == correct_answer.lower()
                feedback = ""
            graded.append(
                {
                    "question": question,
                    "correct": correct_answer,
                    "user": user_answer,
                    "is_correct": is_correct,
                    "feedback": feedback,
                    "image_url": image_url,
                }
            )
            if is_correct:
                correct_count += 1

        results = {
            "total": len(items),
            "correct": correct_count,
            "items": graded,
        }

        if current_user.role == "student":
            attempt = QuizAttempt(
                quiz_id=quiz.id,
                student_id=current_user.id,
                score_correct=correct_count,
                score_total=len(items),
                results_json=json.dumps(graded),
            )
            db.session.add(attempt)
            db.session.commit()

    return render_template("quiz_detail.html", quiz=quiz, items=items, results=results)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("is_admin"):
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        admin_user = app.config.get("ADMIN_USERNAME", "")
        admin_pass = app.config.get("ADMIN_PASSWORD", "")

        if not admin_user or not admin_pass:
            flash("Admin-inloggegevens ontbreken in .env.", "error")
            return redirect(url_for("admin_login"))

        if username == admin_user and password == admin_pass:
            session["is_admin"] = True
            flash("Welkom, admin.", "success")
            return redirect(url_for("admin_dashboard"))

        flash("Ongeldige admin-inloggegevens.", "error")

    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    flash("Admin uitgelogd.", "success")
    return redirect(url_for("index"))


@app.route("/admin")
@require_admin
def admin_dashboard():
    return render_template(
        "admin_dashboard.html",
        openrouter_model=app.config.get("OPENROUTER_MODEL", ""),
        question_max=app.config.get("QUESTION_MAX", 20),
        maintenance_mode=app.config.get("MAINTENANCE_MODE", False),
        env_text=read_env_text(),
    )


@app.route("/admin/maintenance", methods=["POST"])
@require_admin
def admin_maintenance():
    enabled = request.form.get("maintenance_mode") == "on"
    app.config["MAINTENANCE_MODE"] = enabled
    update_env_value("MAINTENANCE_MODE", "on" if enabled else "off")
    flash("Onderhoudsmodus bijgewerkt.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/settings", methods=["POST"])
@require_admin
def admin_settings():
    model = request.form.get("openrouter_model", "").strip()
    question_max = request.form.get("question_max", "").strip()

    if model:
        app.config["OPENROUTER_MODEL"] = model
        update_env_value("OPENROUTER_MODEL", model)

    try:
        value = int(question_max)
    except ValueError:
        value = None

    if value is not None and value > 0:
        app.config["QUESTION_MAX"] = value
        update_env_value("QUESTION_MAX", str(value))

    flash("Instellingen bijgewerkt.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/env", methods=["POST"])
@require_admin
def admin_env_update():
    raw_text = request.form.get("env_text", "")
    if "\x00" in raw_text:
        flash("Ongeldige inhoud in .env.", "error")
        return redirect(url_for("admin_dashboard"))

    env_path = os.path.join(app.config["BASE_DIR"], ".env")
    with open(env_path, "w", encoding="utf-8") as handle:
        handle.write(raw_text.rstrip() + "\n")

    values = parse_env_text(raw_text)
    for key in [
        "SECRET_KEY",
        "OPENROUTER_API_KEY",
        "OPENROUTER_MODEL",
        "OPENROUTER_HELP_MODEL",
        "ADMIN_USERNAME",
        "ADMIN_PASSWORD",
        "GITHUB_CLIENT_ID",
        "GITHUB_CLIENT_SECRET",
        "GITHUB_TEACHER_ORGS",
        "GITHUB_STUDENT_ORGS",
        "GITHUB_TEACHER_DOMAINS",
        "GITHUB_STUDENT_DOMAINS",
        "GITHUB_DEFAULT_ROLE",
        "DATABASE_URL",
    ]:
        if key in values:
            app.config[key] = values[key]

    if "QUESTION_MAX" in values:
        try:
            app.config["QUESTION_MAX"] = int(values["QUESTION_MAX"])
        except ValueError:
            pass

    if "MAINTENANCE_MODE" in values:
        app.config["MAINTENANCE_MODE"] = values["MAINTENANCE_MODE"].lower() == "on"

    database_url = values.get("DATABASE_URL", "")
    if database_url:
        if database_url.startswith("sqlite:"):
            app.config["SQLALCHEMY_DATABASE_URI"] = database_url
        else:
            app.config["SQLALCHEMY_DATABASE_URI"] = database_url

    flash(".env bijgewerkt. Herstart de app voor alle wijzigingen.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/cleanup", methods=["POST"])
@require_admin
def admin_cleanup():
    clear_uploads_folder()
    log_path = os.path.join(app.config["BASE_DIR"], "log.txt")
    if os.path.exists(log_path):
        try:
            os.remove(log_path)
        except OSError:
            pass
    flash("Uploads en logbestand opgeschoond.", "success")
    return redirect(url_for("admin_dashboard"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        ensure_quiz_subject_column()
        cleanup_uploads()
    app.run(debug=True)
