import json
import datetime

from db import db, User, Task, Event
from flask import Flask, request

db_filename = "schedule.db"
app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///%s" % db_filename
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True

db.init_app(app)
with app.app_context():
    db.create_all()

# Constants for readability purposes
EXTRACT_FAIL = -1
INVALID_TOKEN = -2

def success_response(data, code=200):
    """
    Generalized success response function
    """
    return json.dumps(data), code

def failure_response(message, code=404):
    """
    Generalized failure response function
    """
    return json.dumps({"error": message}), code

def extract_token(request):
    """
    Gets token from [request]
    """
    auth_header = request.headers.get('Authorization')
    if auth_header is None:
        return False, json.dumps({'Missing authorization token'})
    bearer_token = auth_header.replace('Bearer', '').strip()
    return True, bearer_token

def get_user_by_session_token(token):
    """
    Gets the user with the session token [token]
    """
    return User.query.filter(User.session_token == token).first()

def get_user_by_update_token(token):
    """
    Gets the user with the update token [token]
    """
    return User.query.filter(User.update_token == token).first()

def get_user_by_id(user_id):
    return User.query.filter(User.id == user_id).first()

def get_user_from_request(request):
    """
    Gets the user_id from the [request]
    """
    success, token = extract_token(request)
    if not success:
        return EXTRACT_FAIL
    user = get_user_by_session_token(token)
    if not user or not user.verify_session_token(token):
        return INVALID_TOKEN
    return user.id

@app.route("/api/register/", methods=["POST"])
def register_account():
    """
    Endpoint for registering a new user with email and password from post
    """
    body = json.loads(request.data)
    username = body.get('username')
    password = body.get('password')

    if username is None or password is None:
        return failure_response('Missing username or password')
    
    user = User.query.filter(User.username == username).first()

    if user is not None:
        return failure_response('User exists')
    
    user = User(username=username, password=password)

    db.session.add(user)
    db.session.commit()

    return success_response(
        {
            'session_token': user.session_token,
            'session_expiration': str(user.session_expiration),
            'update token': user.update_token

        }, 201
    )

@app.route("/api/login/", methods=["POST"])
def login():
    """
    Endpoint for logging in a user
    """
    body = json.loads(request.data)
    username = body.get('username')
    password = body.get('password')

    if username is None or password is None:
        return failure_response('Missing email or password', 400)

    user = User.query.filter(User.username == username).first()
    
    if not user or not user.verify_password(password):
        return failure_response('Username or password not correct', 400)

    return success_response(
        {
            'session_token': user.session_token,
            'session_expiration': str(user.session_expiration),
            'update_token': user.update_token
        }
    )

@app.route("/api/session/", methods=["POST"])
def update_session():
    """
    Endpoint for updating a user's session
    """
    was_successful, update_token = extract_token(request)

    if not was_successful:
        return update_token
    
    user = get_user_by_update_token(update_token)
    
    if user is None:
        return failure_response('Not a valid update token', 400)
    
    user.renew_session()
    db.session.commit()

    return success_response(
        {
            'session_token': user.session_token,
            'session_expiration': str(user.session_expiration),
            'update_token': user.update_token
        }
    )

@app.route('/api/logout/', methods = ['POST'])
def logout():
    user_id = get_user_from_request(request)

    user = get_user_by_id(user_id)
    if user is None:
        return failure_response('User not found', 404)
    
    user.session_expiration = datetime.datetime.now()
    db.session.commit()

    return success_response({'message': 'You have logged out'})

@app.route('/api/tasks/', methods = ['POST'])
def add_task():
    """
    Create a task
    """
    user_id = get_user_from_request(request)
    if user_id == EXTRACT_FAIL:
        return failure_response('Failed to extract token', 400)
    elif user_id == INVALID_TOKEN:
        return failure_response('Invalid token', 400)
    
    body = json.loads(request.data)
    task_name = body.get('task_name')
    due_date = body.get('due_date')
    completed = body.get('completed')
    priority = body.get('priority')

    if task_name is None or due_date is None or completed is None or priority is None:
        return failure_response('One or more fields not supplied', 400)
    
    new_task = Task(
        user_id = user_id,
        task_name = task_name,
        due_date = due_date,
        completed = completed,
        priority = priority
    )

    db.session.add(new_task)
    db.session.commit()
    return success_response(new_task.serialize(), 201)

@app.route('/api/tasks/')
def get_tasks():
    """
    Get all tasks for a given user
    """
    user_id = get_user_from_request(request)
    if user_id == EXTRACT_FAIL:
        return failure_response('Failed to extract token', 400)
    elif user_id == INVALID_TOKEN:
        return failure_response('Invalid token', 400)
    
    user = get_user_by_id(user_id)

    if user is None:
        return failure_response('Failed to get user')

    return success_response(user.get_all_tasks())

@app.route('/api/tasks/<int:task_id>/')
def get_task_by_id(task_id):
    """
    Get task with id [task_id]
    """
    user_id = get_user_from_request(request)
    if user_id == EXTRACT_FAIL:
        return failure_response('Failed to extract token', 400)
    elif user_id == INVALID_TOKEN:
        return failure_response('Invalid token', 400)
        
    task = Task.query.filter_by(id=task_id).first()

    if task is None:
        return failure_response('Task not found')
    elif task.user_id != user_id:
        # The user didn't create the task, so the user is not allowed to access
        return failure_response('You can not access this task', 401)

    return success_response(task.serialize())

@app.route('/api/tasks/<int:task_id>/', methods = ['POST'])
def update_task(task_id):
    """
    Update the task specified by [task_id]
    """
    user_id = get_user_from_request(request)
    if user_id == EXTRACT_FAIL:
        return failure_response('Failed to extract token', 400)
    elif user_id == INVALID_TOKEN:
        return failure_response('Invalid token', 400)
    
    task = Task.query.filter_by(id=task_id).first()
    if task is None:
        return failure_response('Task not found')
    elif task.user_id != user_id:
        # The user didn't create the task, so the user is not allowed to access
        return failure_response('You can not access this task', 401)
    
    body = json.loads(request.data)
    title = body.get('title')
    description = body.get('description')
    time = body.get('time')
    done = body.get('done')

    # Update fields if they are supplied (not null)
    if title is not None:
        task.title = title
    if description is not None:
        task.description = description
    if time is not None:
        task.time = time
    if done is not None:
        task.done = done
    
    db.session.commit()
    return success_response(task.serialize())

@app.route('/api/tasks/<int:task_id>/', methods = ['DELETE'])
def delete_task(task_id):
    """
    Delete the task specified by [task_id]
    """
    user_id = get_user_from_request(request)
    if user_id == EXTRACT_FAIL:
        return failure_response('Failed to extract token', 400)
    elif user_id == INVALID_TOKEN:
        return failure_response('Invalid token', 400)
    
    task = Task.query.filter_by(id=task_id).first()
    if task is None:
        return failure_response('Task not found')
    elif task.user_id != user_id:
        # The user didn't create the task, so the user is not allowed to access
        return failure_response('You can not access this task', 401)
    
    db.session.delete(task)
    db.session.commit()
    return success_response(task.serialize())

@app.route('/api/events/')
def get_events():
    """
    Gets all events for a given user
    """
    user_id = get_user_from_request(request)
    if user_id == EXTRACT_FAIL:
        return failure_response('Failed to extract token', 400)
    elif user_id == INVALID_TOKEN:
        return failure_response('Invalid token', 400)
    
    user = get_user_by_id(user_id)

    if user is None:
        return failure_response('Failed to get user')

    return success_response(user.get_all_events())

@app.route('/api/events/', methods=['POST'])
def create_event():
    """
    Gets all events for a given user
    """
    user_id = get_user_from_request(request)
    if user_id == EXTRACT_FAIL:
        return failure_response('Failed to extract token', 400)
    elif user_id == INVALID_TOKEN:
        return failure_response('Invalid token', 400)
    
    body = json.loads(request.data)

    event_name = body.get('event_name')
    description = body.get('description')
    start_time = body.get('start_time')
    end_time = body.get('end_time')
    color = body.get('color')

    if event_name is None or description is None or start_time is None or end_time is None or color is None:
        return failure_response('One or more fields not supplied', 400)

    new_event = Event(event_name=event_name, description=description, start_time=start_time,
    end_time=end_time, color=color, user_id=user_id)

    db.session.add(new_event)
    db.session.commit()

    return success_response(new_event.serialize(), 201)

@app.route('/api/events/<int:event_id>/')
def get_event_by_id(event_id):
    """
    Get event with id [event_id]
    """
    user_id = get_user_from_request(request)
    if user_id == EXTRACT_FAIL:
        return failure_response('Failed to extract token', 400)
    elif user_id == INVALID_TOKEN:
        return failure_response('Invalid token', 400)
        
    event = Event.query.filter_by(id=event_id).first()

    if event is None:
        return failure_response('Event not found')
    elif event.user_id != user_id:
        # The user didn't create the task, so the user is not allowed to access
        return failure_response('You can not access this event', 401)

    return success_response(event.serialize())

@app.route('/api/events/<int:event_id>/', methods = ['POST'])
def update_event(event_id):
    """
    Update the task specified by [event_id]
    """
    user_id = get_user_from_request(request)
    if user_id == EXTRACT_FAIL:
        return failure_response('Failed to extract token', 400)
    elif user_id == INVALID_TOKEN:
        return failure_response('Invalid token', 400)
    
    event = Event.query.filter_by(id=event_id).first()
    if event is None:
        return failure_response('Event not found')
    elif event.user_id != user_id:
        # The user didn't create the task, so the user is not allowed to access
        return failure_response('You can not access this event', 401)
    
    body = json.loads(request.data)
    
    event_name = body.get('event_name')
    description = body.get('description')
    start_time = body.get('start_time')
    end_time = body.get('end_time')
    color = body.get('color')

    # Update fields if they are supplied (not null)
    if event_name is not None:
        event.event_name = event_name
    if description is not None:
        event.description = description
    if start_time is not None:
        event.start_time = start_time
    if end_time is not None:
        event.end_time = end_time
    if color is not None:
        event.color = color
    
    db.session.commit()
    return success_response(event.serialize())

@app.route('/api/events/<int:event_id>/', methods = ['DELETE'])
def delete_event(event_id):
    """
    Delete the event specified by [event_id]
    """
    user_id = get_user_from_request(request)
    if user_id == EXTRACT_FAIL:
        return failure_response('Failed to extract token', 400)
    elif user_id == INVALID_TOKEN:
        return failure_response('Invalid token', 400)
    
    event = Event.query.filter_by(id=event_id).first()
    if event is None:
        return failure_response('Event not found')
    elif event.user_id != user_id:
        # The user didn't create the event, so the user is not allowed to access
        return failure_response('You can not access this event', 401)
    
    db.session.delete(event)
    db.session.commit()
    return success_response(event.serialize())

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
