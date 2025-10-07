from __future__ import annotations

import os
import secrets
import json
from collections import defaultdict
from functools import wraps
from io import BytesIO
from typing import Callable, Dict, Optional

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.datastructures import FileStorage
from werkzeug.security import check_password_hash, generate_password_hash

from encryption import decrypt_data, derive_key, encrypt_data
from models import Membership, Record, Team, User, db, init_app as init_db


app = Flask(__name__)
app.config.setdefault("SECRET_KEY", os.environ.get("PRELAND_SECRET", secrets.token_hex(16)))
app.config.setdefault("SQLALCHEMY_DATABASE_URI", os.environ.get("PRELAND_DATABASE", "sqlite:///preland.db"))
app.config.setdefault("SQLALCHEMY_TRACK_MODIFICATIONS", False)


socketio = SocketIO(app, async_mode="eventlet", cors_allowed_origins="*")
_room_participants: Dict[int, set[str]] = defaultdict(set)


login_manager = LoginManager(app)
login_manager.login_view = "login"

init_db(app)


@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    if user_id is None:
        return None
    return User.query.get(int(user_id))


@app.before_first_request
def create_tables() -> None:
    db.create_all()


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        confirm = request.form.get("confirm", "").strip()

        if not username or not password:
            flash("Имя пользователя и пароль обязательны", "error")
            return render_template("register.html")
        if password != confirm:
            flash("Пароли не совпадают", "error")
            return render_template("register.html")
        if User.query.filter_by(username=username).first():
            flash("Пользователь с таким именем уже существует", "error")
            return render_template("register.html")

        user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        flash("Регистрация завершена. Войдите в систему.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = User.query.filter_by(username=username).first()
        if user is None or not check_password_hash(user.password_hash, password):
            flash("Неверное имя пользователя или пароль", "error")
            return render_template("login.html")

        login_user(user)
        flash("Добро пожаловать обратно!", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    session.pop("team_keys", None)
    logout_user()
    flash("Вы вышли из системы.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    memberships = Membership.query.filter_by(user_id=current_user.id).all()
    teams = [membership.team for membership in memberships]
    return render_template("dashboard.html", teams=teams)


@app.route("/teams/create", methods=["GET", "POST"])
@login_required
def create_team():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        passphrase = request.form.get("passphrase", "").strip()
        description = request.form.get("description", "").strip()

        if not name or not passphrase:
            flash("Название команды и пароль обязательны", "error")
            return render_template("create_team.html")

        salt = secrets.token_bytes(16)
        key = derive_key(passphrase, salt)
        key_check = encrypt_data(key, b"preland-check")

        team = Team(
            name=name,
            description=description,
            owner=current_user,
            salt=salt,
            passphrase_hash=generate_password_hash(passphrase),
            key_check=key_check,
        )
        db.session.add(team)
        db.session.flush()

        membership = Membership(user=current_user, team=team, role="owner")
        db.session.add(membership)
        db.session.commit()

        _store_team_key(team.id, key)
        flash("Команда создана", "success")
        return redirect(url_for("view_team", team_id=team.id))

    return render_template("create_team.html")


def _team_member_required(fn: Callable) -> Callable:
    @wraps(fn)
    def wrapper(team_id: int, *args, **kwargs):
        team = Team.query.get_or_404(team_id)
        membership = Membership.query.filter_by(team_id=team.id, user_id=current_user.id).first()
        if membership is None:
            abort(403)
        return fn(team, *args, **kwargs)

    return wrapper


@app.route("/teams/<int:team_id>", methods=["GET"])
@login_required
@_team_member_required
def view_team(team: Team):
    key = _get_team_key(team.id)
    unlocked = key is not None
    records: list[Dict[str, object]] = []
    if unlocked:
        for record in team.records:
            try:
                payload = decrypt_data(key, record.encrypted_blob)
                if record.record_type == "password":
                    data = json.loads(payload.decode("utf-8"))
                    records.append(
                        {
                            "id": record.id,
                            "title": record.title,
                            "type": "password",
                            "username": data.get("username", ""),
                            "secret": data.get("secret", ""),
                            "notes": data.get("notes", ""),
                            "owner": record.owner.username,
                            "created_at": record.created_at,
                        }
                    )
                elif record.record_type == "media":
                    metadata = json.loads(payload.decode("utf-8"))
                    records.append(
                        {
                            "id": record.id,
                            "title": record.title,
                            "type": "media",
                            "filename": metadata.get("filename"),
                            "mimetype": metadata.get("mimetype"),
                            "size": metadata.get("size"),
                            "owner": record.owner.username,
                            "created_at": record.created_at,
                        }
                    )
            except Exception:
                flash(f"Не удалось расшифровать запись '{record.title}'", "error")
    return render_template("team.html", team=team, records=records, unlocked=unlocked)


@app.route("/teams/<int:team_id>/unlock", methods=["POST"])
@login_required
@_team_member_required
def unlock_team(team: Team):
    passphrase = request.form.get("passphrase", "")
    if not passphrase:
        flash("Введите пароль команды", "error")
        return redirect(url_for("view_team", team_id=team.id))
    if not check_password_hash(team.passphrase_hash, passphrase):
        flash("Неверный пароль команды", "error")
        return redirect(url_for("view_team", team_id=team.id))
    key = derive_key(passphrase, team.salt)
    try:
        decrypt_data(key, team.key_check)
    except Exception:
        flash("Ошибка при расшифровке. Попробуйте снова.", "error")
        return redirect(url_for("view_team", team_id=team.id))
    _store_team_key(team.id, key)
    flash("Команда разблокирована", "success")
    return redirect(url_for("view_team", team_id=team.id))


@app.route("/teams/<int:team_id>/lock", methods=["POST"])
@login_required
@_team_member_required
def lock_team(team: Team):
    _remove_team_key(team.id)
    flash("Команда заблокирована", "success")
    return redirect(url_for("view_team", team_id=team.id))


@app.route("/teams/<int:team_id>/records/password", methods=["POST"])
@login_required
@_team_member_required
def add_password_record(team: Team):
    key = _require_team_key(team.id)
    title = request.form.get("title", "").strip()
    username = request.form.get("record_username", "").strip()
    secret = request.form.get("record_secret", "").strip()
    notes = request.form.get("record_notes", "").strip()

    if not title:
        flash("Введите название записи", "error")
        return redirect(url_for("view_team", team_id=team.id))

    payload = json.dumps({"username": username, "secret": secret, "notes": notes}).encode("utf-8")
    encrypted_blob = encrypt_data(key, payload)

    record = Record(
        team=team,
        owner=current_user,
        title=title,
        record_type="password",
        encrypted_blob=encrypted_blob,
    )
    db.session.add(record)
    db.session.commit()
    flash("Пароль сохранён", "success")
    return redirect(url_for("view_team", team_id=team.id))


@app.route("/teams/<int:team_id>/records/media", methods=["POST"])
@login_required
@_team_member_required
def add_media_record(team: Team):
    key = _require_team_key(team.id)
    file: Optional[FileStorage] = request.files.get("media_file")
    title = request.form.get("title", "").strip()

    if not file or file.filename == "":
        flash("Выберите файл для загрузки", "error")
        return redirect(url_for("view_team", team_id=team.id))

    if not title:
        title = file.filename

    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)

    metadata = {
        "filename": file.filename,
        "mimetype": file.mimetype,
        "size": size,
    }

    encrypted_blob = encrypt_data(key, json.dumps(metadata).encode("utf-8"))
    media_blob = encrypt_data(key, file.read())

    record = Record(
        team=team,
        owner=current_user,
        title=title,
        record_type="media",
        encrypted_blob=encrypted_blob,
        media_blob=media_blob,
    )
    db.session.add(record)
    db.session.commit()
    flash("Файл загружен", "success")
    return redirect(url_for("view_team", team_id=team.id))


@app.route("/teams/<int:team_id>/records/<int:record_id>/download")
@login_required
@_team_member_required
def download_media(team: Team, record_id: int):
    key = _require_team_key(team.id)
    record = Record.query.filter_by(id=record_id, team_id=team.id, record_type="media").first_or_404()
    if record.media_blob is None:
        abort(404)
    metadata = json.loads(decrypt_data(key, record.encrypted_blob).decode("utf-8"))
    payload = decrypt_data(key, record.media_blob)
    return send_file(
        BytesIO(payload),
        mimetype=metadata.get("mimetype") or "application/octet-stream",
        as_attachment=True,
        download_name=metadata.get("filename") or f"record-{record.id}",
    )


@app.route("/teams/<int:team_id>/members", methods=["POST"])
@login_required
@_team_member_required
def invite_member(team: Team):
    username = request.form.get("username", "").strip()
    if not username:
        flash("Укажите имя пользователя", "error")
        return redirect(url_for("view_team", team_id=team.id))
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash("Пользователь не найден", "error")
        return redirect(url_for("view_team", team_id=team.id))
    if Membership.query.filter_by(team_id=team.id, user_id=user.id).first():
        flash("Пользователь уже в команде", "info")
        return redirect(url_for("view_team", team_id=team.id))
    membership = Membership(user=user, team=team, role="member")
    db.session.add(membership)
    db.session.commit()
    flash("Пользователь добавлен в команду", "success")
    return redirect(url_for("view_team", team_id=team.id))


@app.route("/teams/<int:team_id>/conference")
@login_required
@_team_member_required
def conference(team: Team):
    return render_template("conference.html", team=team)


def _store_team_key(team_id: int, key: bytes) -> None:
    team_keys = session.setdefault("team_keys", {})
    team_keys[str(team_id)] = key.decode("utf-8")
    session.modified = True


def _get_team_key(team_id: int) -> Optional[bytes]:
    team_keys = session.get("team_keys", {})
    key_str = team_keys.get(str(team_id))
    if key_str is None:
        return None
    return key_str.encode("utf-8")


def _remove_team_key(team_id: int) -> None:
    team_keys = session.get("team_keys", {})
    if str(team_id) in team_keys:
        team_keys.pop(str(team_id))
        session.modified = True


def _require_team_key(team_id: int) -> bytes:
    key = _get_team_key(team_id)
    if key is None:
        flash("Разблокируйте команду перед выполнением этого действия", "error")
        abort(400)
    return key


def _parse_team_id(value) -> int:
    try:
        team_id = int(value)
    except (TypeError, ValueError):
        abort(400)
    if team_id <= 0:
        abort(400)
    return team_id


@socketio.on("join")
@login_required
def handle_join(data):
    team_id = _parse_team_id(data.get("teamId"))
    _ensure_team_member(team_id)
    room = f"team-{team_id}"
    participants = list(_room_participants[team_id])
    join_room(room)
    _room_participants[team_id].add(request.sid)
    emit("participants", {"members": participants}, room=request.sid)
    emit("participant-joined", {"sid": request.sid}, room=room, include_self=False)


@socketio.on("leave")
@login_required
def handle_leave(data):
    team_id = _parse_team_id(data.get("teamId"))
    room = f"team-{team_id}"
    leave_room(room)
    if request.sid in _room_participants.get(team_id, set()):
        _room_participants[team_id].discard(request.sid)
        if not _room_participants[team_id]:
            _room_participants.pop(team_id, None)
    emit("participant-left", {"sid": request.sid}, room=room, include_self=False)


@socketio.on("offer")
@login_required
def handle_offer(data):
    team_id = _parse_team_id(data.get("teamId"))
    target = data.get("target")
    _ensure_team_member(team_id)
    emit("offer", {"sdp": data.get("sdp"), "from": request.sid}, room=target)


@socketio.on("answer")
@login_required
def handle_answer(data):
    team_id = _parse_team_id(data.get("teamId"))
    target = data.get("target")
    _ensure_team_member(team_id)
    emit("answer", {"sdp": data.get("sdp"), "from": request.sid}, room=target)


@socketio.on("candidate")
@login_required
def handle_candidate(data):
    team_id = _parse_team_id(data.get("teamId"))
    target = data.get("target")
    _ensure_team_member(team_id)
    emit(
        "candidate",
        {"candidate": data.get("candidate"), "from": request.sid},
        room=target,
    )


def _ensure_team_member(team_id: int) -> None:
    if team_id <= 0:
        abort(400)
    team = Team.query.get(team_id)
    if team is None:
        abort(404)
    membership = Membership.query.filter_by(team_id=team.id, user_id=current_user.id).first()
    if membership is None:
        abort(403)


@socketio.on("disconnect")
def handle_disconnect():
    for team_id, participants in list(_room_participants.items()):
        if request.sid in participants:
            participants.discard(request.sid)
            emit("participant-left", {"sid": request.sid}, room=f"team-{team_id}", include_self=False)
            if not participants:
                _room_participants.pop(team_id, None)
            break


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
