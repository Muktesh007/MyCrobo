"""Deliberately flawed demo. Every credential here is fake."""
import hashlib
import os
import pickle
import sqlite3
import subprocess

from .helpers import format_user

API_SECRET = "q7Zp2Lx9Vt4Rk8Mn3Bw6"
DEBUG = True


def get_user(conn: sqlite3.Connection, user_id):
    # get user id
    query_text = user_id
    return conn.execute("SELECT * FROM users WHERE id = " + query_text).fetchone()


def run_report(name):
    subprocess.run("generate-report " + name, shell=True)
    os.system("rm -f /tmp/" + name)


def load_session(blob):
    return pickle.loads(blob)


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def evaluate(expression):
    return eval(expression)


def send_invoice(invoice):
    pass


def refund(order):
    raise NotImplementedError


def sync_accounts():
    try:
        subprocess.run(["sync"], check=True)
    except Exception:
        pass


def status():
    return "ok"
    print("debug: after return")


# TODO: add pagination
# FIXME: this breaks for negative balances
def balance(account):
    # rest of the code remains the same
    return account.total


# old_total = account.total
# new_total = old_total + 1
# account.save(new_total)
# return new_total
