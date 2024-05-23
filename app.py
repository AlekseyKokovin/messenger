import os
import random
from datetime import datetime
from email.mime.multipart import MIMEMultipart

import flask_login
import requests
from flask import Flask, redirect, render_template, request, session, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user
from flask_socketio import SocketIO, emit
from sqlalchemy import select, or_, and_
from gevent.pywsgi import WSGIServer
from geventwebsocket.handler import WebSocketHandler
from data import db_session
from data.db_session import global_init
from data.message import Message
from data.user import User
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
socketio = SocketIO(app)
login_manager = LoginManager()
login_manager.init_app(app)
language_short = {
    'english': 'en',
    'russian': 'ru',
    'spanish': 'es',
    'french': 'fr',
    'german': 'de',
    'italian': 'it',
    'chinese': 'zh',
    'japanese': 'ja',
    'korean': 'ko',
    'arabic': 'ar'
}


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


@app.errorhandler(401)
def unauthorized(error):
    return redirect('/')


@login_manager.user_loader
def load_user(user_id):
    db_sess = db_session.create_session()
    return db_sess.get(User, user_id)


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        db_sess = db_session.create_session()
        user = db_sess.execute(select(User).where(User.email == request.form.get('email'))).first()
        if user and user[0].check_password(request.form.get('password')):
            user = user[0]
            if user.twofa:
                session['remember'] = True if request.form.get('rememberMe') == 'on' else False
                session['email'] = request.form.get('email')
                return redirect("/two_factor")
            login_user(user, remember=True if request.form.get('rememberMe') == 'on' else False)
            return redirect("/main_chats")
        if not user:
            return render_template('login.html', message="Аккаунта с таким логин не существует")
        return render_template('login.html', message="Неправильный логин или пароль")
    return render_template('login.html')


@app.route('/two_factor', methods=['GET', 'POST'])
def two_factor_auth():
    if 'email' not in session or 'remember' not in session:
        return redirect('/')
    if request.method == 'POST':
        if session['code'] == request.form.get('confirmation'):
            db_sess = db_session.create_session()
            user = db_sess.execute(select(User).where(User.email == str(session['email']))).first()[0]
            remember = session['remember']
            session.pop('remember', None)
            session.pop('code', None)
            session.pop('user', None)
            login_user(user, remember=remember)
            return redirect("/main_chats")
        return render_template('verify_email_login.html', message="Неправильный код")
    if 'code' not in session:
        email = session['email']
        session['code'] = ''.join(random.choices('0123456789', k=6))
        sender = "yandexproject9@gmail.com"
        password = "kfjfhukstqonsvsb"
        send_email(sender, email, password, session['code'])
    return render_template('verify_email_login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if password != confirm_password:
            return render_template('register_step1.html', message='Passwords do not match!')
        db_sess = db_session.create_session()
        existing_user = db_sess.execute(select(User).where(User.email == email)).first()
        if existing_user:
            return render_template('register_step1.html', message='Email already exists!')
        session['email'] = email
        session['password'] = password
        return redirect('/register_step2')
    return render_template('register_step1.html')


@app.route('/register_step2', methods=['GET', 'POST'])
def register_step2():
    if 'email' not in session or 'password' not in session:
        return redirect('/register')
    if request.method == 'POST':
        username = request.form.get('username')
        surname = request.form.get('surname')
        name = request.form.get('name')
        session['username'] = username
        session['surname'] = surname
        session['name'] = name
        session['language'] = request.form['language']
        db_sess = db_session.create_session()
        existing_user = db_sess.execute(select(User).where(User.username == username)).first()
        if existing_user:
            return render_template('register_step2.html', message='Such username already exists!')
        return redirect('/register_step3')
    return render_template('register_step2.html')


@app.route('/register_step3', methods=['GET', 'POST'])
def confirm_mail():
    if 'email' not in session or 'password' not in session:
        return redirect('/register')
    if 'username' not in session or 'surname' not in session or 'name' not in session:
        return redirect('/register_step2')
    email = session['email']
    if request.method == 'POST':
        username = session['username']
        surname = session['surname']
        language = session['language']
        name = session['name']
        password = session['password']
        if request.form.get('confirmation') != session['code']:
            return render_template('verify_email_register.html', message='Invalid confirmation code')
        new_user = User()
        new_user.name = name
        new_user.username = username
        new_user.email = email
        new_user.language = language_short[language]
        new_user.surname = surname
        new_user.twofa = True if request.form.get('2fa') == 'on' else None
        new_user.set_password(password)
        db_sess = db_session.create_session()
        db_sess.add(new_user)
        db_sess.commit()
        session.pop('email', None)
        session.pop('password', None)
        session.pop('username', None)
        session.pop('surname', None)
        session.pop('name', None)
        session.pop('code', None)
        login_user(new_user, remember=False)
        return redirect('/main_chats')
    if 'code' not in session:
        session['code'] = ''.join(random.choices('0123456789', k=6))
        sender = "yandexproject9@gmail.com"
        password = "obsf dnrh knqr dlvi"
        send_email(sender, email, password, session['code'])
    return render_template('verify_email_register.html')


def send_email(sender, recipient, password, verification_code):
    msg = MIMEMultipart('alternative')
    msg['From'] = sender
    msg['To'] = recipient
    msg['Subject'] = "Email Verification"
    html = f"""
    <html>
    <head>
    <title>Welcome to [Your Website Name]</title>
    </head>
    <body style="font-family: Arial, sans-serif;">
    <p>Thank you for registering! Verify your email address.</p>
    <p>Please use the following <strong>6-digit verification code</strong> to complete your registration:</p>
    <h3 style="background-color: #f5f5f5; padding: 10px; width: 100px; border-radius: 5px;">{verification_code}</h3>
    <p>Enter this code on the registration page to verify your email address. If you didn't request this verification, 
    please ignore this email.</p>
    </body>
    </html>
       """
    msg.attach(MIMEText(html, 'html'))
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender, password)
    server.sendmail(sender, recipient, msg.as_string())
    server.quit()


@app.route('/main_chats')
@login_required
def index():
    db_sess = db_session.create_session()
    users = list(map(lambda x: x[0].username, sorted(db_sess.execute(select(User)).fetchall(), reverse=True,
                                                     key=lambda x: x[0].latest_messagee if
                                                     x[0].latest_messagee else datetime(2024, 4, 30, 1, 1, 1))))
    users_with_messages = list(map(lambda x: x, filter(lambda x: db_sess.execute(select(Message).where(
        or_(
            and_(Message.sender_handle == x, Message.receiver_handle == flask_login.current_user.username),
            and_(Message.sender_handle == flask_login.current_user.username, Message.receiver_handle == x)
        ))).fetchall(), users)))
    return render_template('main_for_chats.html', users_with_messages=users_with_messages,
                           current_username=flask_login.current_user.username, users=users)


@app.route('/get_users_with_messages')
@login_required
def get_users_with_messages():
    db_sess = db_session.create_session()
    users = list(map(lambda x: x[0].username, sorted(db_sess.execute(select(User)).fetchall(), reverse=True,
                                                     key=lambda x: x[0].latest_messagee if
                                                     x[0].latest_messagee else datetime(2024, 4, 30, 1, 1, 1))))
    users_with_messages = list(map(lambda x: x, filter(lambda x: db_sess.execute(select(Message).where(
        or_(
            and_(Message.sender_handle == x, Message.receiver_handle == flask_login.current_user.username),
            and_(Message.sender_handle == flask_login.current_user.username, Message.receiver_handle == x)
        ))).fetchall(), users)))
    return jsonify(users_with_messages)


@socketio.on('message')
@login_required
def handle_message(data):
    db_sess = db_session.create_session()
    user = db_sess.execute(select(User).where(User.username == str(flask_login.current_user.username))).first()[0]
    user.latest_messagee = datetime.now()
    user1 = db_sess.execute(select(User).where(User.username == str(data.get('receiver_username')))).first()[0]
    user1.latest_messagee = datetime.now()
    message = Message()
    message.sender_handle = flask_login.current_user.username
    message.receiver_handle = data.get('receiver_username')
    message.text = data.get('text')
    message.time = datetime.now()
    message.unread = user1.disconnected
    db_sess.add(message)
    db_sess.commit()
    emit('message_send',
         {"sender_username": flask_login.current_user.username, 'receiver_username': data.get('receiver_username'),
          'text': data.get('text')}, broadcast=True)


@app.route('/get_messages/<username>')
@login_required
def get_messages(username):
    db_sess = db_session.create_session()
    messages = db_sess.execute(
        select(Message).where(
            or_(
                (Message.sender_handle == flask_login.current_user.username) & (Message.receiver_handle == username),
                (Message.sender_handle == username) & (Message.receiver_handle == flask_login.current_user.username)
            )
        )
    ).fetchall()
    messages_unread = db_sess.execute(select(Message).where(
        (Message.sender_handle == username) & (Message.receiver_handle == flask_login.current_user.username) & (
                Message.unread == 1))).fetchall()
    messages_data = [{'sender_handle': str(message[0].sender_handle), 'text': str(message[0].text),
                      "unread": True if messages_unread else False} for message in messages]
    return jsonify(messages_data)


@app.route('/get_connected/<username>')
def get_connected(username):
    db_sess = db_session.create_session()
    user = db_sess.execute(select(User).where(User.username == str(username))).first()[0]
    return jsonify(user.disconnected)


@app.route('/get_translation/<user>/<text>')
@login_required
def get_translation(user, text):
    translated_text = translate_text(text, flask_login.current_user.language)
    return translated_text


def translate_text(text, language):
    url = f"https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&tl={language}&dt=t&q={text}"
    response = requests.get(url)
    if response.status_code == 200:
        translated_text = response.json()[0][0][0]
        return translated_text
    else:
        return "Translation failed"


@socketio.on('disconnect')
@login_required
def handle_disconnect():
    db_sess = db_session.create_session()
    user = db_sess.execute(select(User).where(User.username == str(flask_login.current_user.username))).first()[0]
    user.disconnected = True
    db_sess.commit()


@socketio.on('connect')
@login_required
def handle_disconnect():
    db_sess = db_session.create_session()
    user = db_sess.execute(select(User).where(User.username == str(flask_login.current_user.username))).first()[0]
    user.disconnected = False
    db_sess.commit()


@socketio.on('unread')
@login_required
def handle_disconnect(data):
    db_sess = db_session.create_session()
    message_unread = db_sess.execute(select(Message).where(
        (Message.receiver_handle == str(data.get('receiver_username'))) &
        (Message.sender_handle == str(data.get('sender_username'))) &
        (Message.text == str(data.get('text')))
    )).first()
    if message_unread:
        message_unread = message_unread[0]
    message_unread.unread = 1
    db_sess.commit()


@socketio.on('read')
@login_required
def handle_message(data):
    db_sess = db_session.create_session()
    messages = db_sess.execute(select(Message).where((Message.sender_handle == str(data.get('username'))) & (
            Message.receiver_handle == str(flask_login.current_user.username)) & (Message.unread == 1))).fetchall()
    for i in messages:
        i[0].unread = 0
    db_sess.commit()


if __name__ == '__main__':
    global_init('db/main.db')
    app.config['SECRET_KEY'] = os.urandom(12)
    http_server = WSGIServer(('0.0.0.0', 4444), app, handler_class=WebSocketHandler, keyfile='key.pem',
                             certfile='cert.pem')
    http_server.serve_forever()
