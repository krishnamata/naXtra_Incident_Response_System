from flask import Flask, request, make_response, redirect, url_for, jsonify
from flask_jwt_extended import create_access_token, decode_token, JWTManager
from datetime import timedelta
import logging

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your-secret-key-here'  # change to secure secret

jwt = JWTManager(app)  

logging.basicConfig(level=logging.INFO)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # For testing: accept user 'admin' with password 'admin'
        if username == 'admin' and password == 'admin':
            logging.info(f"User {username} authenticated")

            access_token = create_access_token(identity=username, expires_delta=timedelta(hours=1))

            response = make_response(redirect(url_for('protected')))
            response.set_cookie(
                'access_token',
                access_token,
                httponly=True,
                samesite='Lax',
                max_age=3600
            )
            return response
        else:
            return 'Invalid credentials', 401
    return '''
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit" value="Login">
        </form>
    '''

@app.route('/protected')
def protected():
    token = request.cookies.get('access_token')
    if not token:
        return 'No token provided', 401

    try:
        decoded = decode_token(token)
        username = decoded['sub']
        return f'Hello, {username}. You have access.'
    except Exception as e:
        logging.warning(f'Token error: {e}')
        return 'Invalid or expired token', 401

@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('login')))
    response.delete_cookie('access_token')
    return response

if __name__ == '__main__':
    app.run(debug=True)
