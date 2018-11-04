import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from kfolio.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')


@bp.route('/password', methods=('GET', 'POST'))
@login_required
def change_password():
    if request.method == 'POST':
        user = g.user
        password = request.form['password']
        new_password = request.form['new_password']
        verify = request.form['new_password']

        if not password:
            error = 'Password is required.'
        elif not new_password:
            error = 'Please enter new password'
        elif not verify or new_password != verify:
            error = 'Passwords do not match'
        elif not check_password_hash(user['password'], password):
            error = "Incorrect password"

        if error is None:
            db.execute(
                'UPDATE user SET password = ? WHERE username = Kae',
                (generate_password_hash(new_password))
            )
            db.commit()
            flash("Password updated")
            ##TODO - update this to an appropriate location later
            return redirect(url_for('auth.login'))

    return render_template('auth/password.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))
