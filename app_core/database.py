# INTENTIONALLY VULNERABLE - For security demonstration only

import sqlite3
from datetime import datetime

from config import DATABASE


def init_db():
	conn = sqlite3.connect(DATABASE)
	cur = conn.cursor()

	cur.execute(
		"""
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY,
			username TEXT,
			password TEXT
		)
		"""
	)

	cur.execute(
		"""
		CREATE TABLE IF NOT EXISTS comments (
			id INTEGER PRIMARY KEY,
			username TEXT,
			content TEXT,
			timestamp TEXT
		)
		"""
	)

	# Seed demo users once.
	cur.execute("SELECT COUNT(*) FROM users")
	user_count = cur.fetchone()[0]
	if user_count == 0:
		cur.executemany(
			"INSERT INTO users (username, password) VALUES (?, ?)",
			[
				("admin", "admin123"),
				("alice", "password1"),
				("bob", "letmein"),
			],
		)

	conn.commit()
	conn.close()


def check_login(username, password):
	conn = sqlite3.connect(DATABASE)
	cur = conn.cursor()

	# INTENTIONALLY UNSAFE: vulnerable to SQL injection via f-string interpolation.
	query = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}'"
	cur.execute(query)
	user = cur.fetchone()

	conn.close()
	return user


def get_comments():
	conn = sqlite3.connect(DATABASE)
	cur = conn.cursor()
	cur.execute("SELECT id, username, content, timestamp FROM comments ORDER BY id DESC")
	rows = cur.fetchall()
	conn.close()
	return rows


def add_comment(username, content):
	conn = sqlite3.connect(DATABASE)
	cur = conn.cursor()

	timestamp = datetime.utcnow().isoformat()
	# INTENTIONALLY UNSAFE: direct string formatting into SQL for demonstration.
	query = (
		"INSERT INTO comments (username, content, timestamp) "
		f"VALUES ('{username}', '{content}', '{timestamp}')"
	)
	cur.execute(query)

	conn.commit()
	conn.close()


def get_user_by_id(user_id):
	conn = sqlite3.connect(DATABASE)
	cur = conn.cursor()
	cur.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
	user = cur.fetchone()
	conn.close()
	return user
