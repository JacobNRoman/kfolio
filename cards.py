from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from kfolio.auth import login_required
from kfolio.db import get_db

bp = Blueprint('cards', __name__, url_prefix="/cards")

@bp.route('/')
@login_required
def index():
    db = get_db()
    cards = db.execute(
        'SELECT id, title, body, tag FROM card'
    ).fetchall()
    return render_template('cards/index.html', cards=cards)

@bp.route('/create', methods=('GET', 'POST'))
@login_required
def create():
    if request.method == 'POST':
        title = request.form['title']
        body = request.form['body']
        tag = request.form['tag']
        error = None

        if not title:
            error = 'Title is empty'
        if not body:
            error = 'Body is empty'
        if not tag:
            error = 'Please tag this card'
        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'INSERT INTO card (title, body, tag)'
                ' VALUES (?, ?, ?)',
                (title, body, tag)
            )
            db.commit()
            return redirect(url_for('cards.index'))

    return render_template('cards/create.html')

@bp.route('/<int:id>/update', methods=('GET', 'POST'))
@login_required
def update(id):
    card = get_card(id)

    if request.method == 'POST':
        title = request.form['title']
        body = request.form['body']
        tag = request.form['tag']
        error = None

        if not title:
            error = 'Title is required.'
        if not body:
            error = 'Body is empty'
        if not tag:
            error = "Please add a tag to this card"
        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'UPDATE card SET title = ?, body = ?, tag = ?'
                ' WHERE id = ?',
                (title, body, tag, id)
            )
            db.commit()
            return redirect(url_for('cards.index'))

    return render_template('cards/update.html', card=card)


@bp.route('/<int:id>/delete', methods=('POST',))
@login_required
def delete(id):
    get_card(id)
    db = get_db()
    db.execute('DELETE FROM card WHERE id = ?', (id,))
    db.commit()
    return redirect(url_for('cards.index'))

def get_card(id):
    card = get_db().execute(
        'SELECT id, title, body, tag FROM card'
    ).fetchone()

    if card is None:
        abort(404, "Post id {0} doesn't exist.".format(id))

    return card
