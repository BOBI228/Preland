from __future__ import annotations

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin


db = SQLAlchemy()


def init_app(app) -> None:
    db.init_app(app)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    memberships = db.relationship("Membership", back_populates="user", cascade="all, delete-orphan")
    records = db.relationship("Record", back_populates="owner", cascade="all, delete-orphan")


class Team(db.Model):
    __tablename__ = "teams"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    salt = db.Column(db.LargeBinary(16), nullable=False)
    passphrase_hash = db.Column(db.String(255), nullable=False)
    key_check = db.Column(db.LargeBinary, nullable=False)

    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    owner = db.relationship("User", backref="owned_teams")

    memberships = db.relationship("Membership", back_populates="team", cascade="all, delete-orphan")
    records = db.relationship("Record", back_populates="team", cascade="all, delete-orphan")


class Membership(db.Model):
    __tablename__ = "memberships"
    __table_args__ = (db.UniqueConstraint("user_id", "team_id", name="uq_membership"),)

    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(20), default="member", nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey("teams.id"), nullable=False)

    user = db.relationship("User", back_populates="memberships")
    team = db.relationship("Team", back_populates="memberships")


class Record(db.Model):
    __tablename__ = "records"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    record_type = db.Column(db.String(20), nullable=False)
    encrypted_blob = db.Column(db.LargeBinary, nullable=False)
    media_blob = db.Column(db.LargeBinary)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    team_id = db.Column(db.Integer, db.ForeignKey("teams.id"), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    team = db.relationship("Team", back_populates="records")
    owner = db.relationship("User", back_populates="records")

    @property
    def is_media(self) -> bool:
        return self.record_type == "media"

    @property
    def is_password(self) -> bool:
        return self.record_type == "password"
