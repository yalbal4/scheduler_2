import datetime
import hashlib
import os

import bcrypt
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    """
    User model
    """
    __tablename__ = 'user'

    # User information
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    password_digest = db.Column(db.String, nullable=False)
    events = db.relationship('Event', cascade='delete') 
    tasks = db.relationship('Task', cascade='delete')

    # Session information
    session_token = db.Column(db.String, nullable=False, unique=True)
    session_expiration = db.Column(db.DateTime, nullable=False)
    update_token = db.Column(db.String, nullable=False, unique=True)

    def __init__(self, **kwargs):
        """
        Initializes a User object
        """
        self.username = kwargs.get("username")
        self.password_digest = bcrypt.hashpw(kwargs.get("password").encode("utf8"), bcrypt.gensalt(rounds=13))
        self.renew_session()

    def _urlsafe_base_64(self):
        """
        Randomly generates hashed tokens (used for session/update tokens)
        """
        return hashlib.sha1(os.urandom(64)).hexdigest()

    def renew_session(self):
        """
        Renews the sessions, i.e.
        1. Creates a new session token
        2. Sets the expiration time of the session to be a day from now
        3. Creates a new update token
        """
        self.session_token = self._urlsafe_base_64()
        self.session_expiration = datetime.datetime.now() + datetime.timedelta(days=1)
        self.update_token = self._urlsafe_base_64()

    def verify_password(self, password):
        """
        Verifies the password of a user
        """
        return bcrypt.checkpw(password.encode("utf8"), self.password_digest)

    def verify_session_token(self, session_token):
        """
        Verifies the session token of a user
        """
        return session_token == self.session_token and datetime.datetime.now() < self.session_expiration

    def verify_update_token(self, update_token):
        """
        Verifies the update token of a user
        """
        return update_token == self.update_token
    
    def serialize(self): 
        """
        Convert User object to dictionary
        """ 
        return {
            'id': self.id,
            'events': [e.serialize() for e in self.events],
            'tasks': [t.serialize() for t in self.tasks]
        }
    
    def get_all_tasks(self):
        """
        Gets all tasks for a user
        """
        return {
            'tasks': [t.serialize() for t in self.tasks]
        }
    
    def get_all_events(self):
        """
        Gets all events for a user
        """
        return {
            'events': [e.serialize() for e in self.events]
        }

class Task(db.Model):
    """
    Task has many to one relationship with User
    Fields are id, user_id, title, description, time, done
    """
    __tablename__ = 'task'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    task_name = db.Column(db.String, nullable=False)
    due_date = db.Column(db.Integer, nullable=False)
    completed = db.Column(db.Boolean, nullable=False)
    priority = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, **kwargs):
        """
        Initializes Task object
        """
        self.user_id = kwargs.get('user_id')
        self.task_name = kwargs.get('task_name')
        self.due_date = kwargs.get('due_date')
        self.completed = kwargs.get('completed')
        self.priority = kwargs.get('priority')

    def serialize(self):
        """
        Serializes the task
        """
        return{
            'task_id': self.id,
            'task_name': self.task_name,
            'due_date': str(self.due_date),
            'completed': self.completed,
            'priority': self.priority
        }

class Event(db.Model):
    """
    Event model: has a many-to-one relationship with User
    """
    __tablename__ = 'event'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    event_name = db.Column(db.String, nullable=False)
    description = db.Column(db.String)
    start_time = db.Column(db.Integer, nullable=False)
    end_time = db.Column(db.Integer, nullable=False)
    color = db.Column(db.String)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init(self, **kwargs): 
        """
        Initialize Task object
        """
        self.event_name = kwargs.get('event_name')
        self.description('description')
        self.start_time = kwargs.get('start_time')
        self.end_time = kwargs.get('end_time')
        self.color = kwargs.get('color')
        self.user_id = kwargs.get('user_id')

    def serialize(self):
        """
        Convert Event object to dictionary
        """
        return {
            'id': self.id,
            'event_name': self.event_name,
            'description': self.description,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'color': self.color
        }