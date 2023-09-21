from flask import Flask, request
import os

app = Flask(__name__)


@app.before_request
def before_request_func():
    user_agent = request.headers.get('User-Agent')
    log_message = f'Request from {request.remote_addr}, User-Agent: {user_agent}'
    
    # sanitise
    log_message = log_message.replace('"', '\\"')

    # Devs were too lazy to open files and write to them, so they YOLOed it with "echo"
    os.system(f'echo "{log_message}" >> server.log')


@app.route('/')
def get_home():
    return 'Totally secure application!'


app.run('0.0.0.0', 1337)
