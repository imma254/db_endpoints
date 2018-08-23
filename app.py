from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps


app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:soen30010010@localhost/flask_app'
db = SQLAlchemy(app)


class User(db.Model):
    """docstring for User"""
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50))
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


class Questions(db.Model):
    """docstring for Todo"""
    id = db.Column(db.Integer, primary_key=True)
    topic = db.Column(db.String(50))
    question = db.Column(db.String, unique=True)
    user_id = db.Column(db.Integer)
    votes = db.Column(db.Integer)


class Answers(db.Model):
    """docstring for Answers"""
    id = db.Column(db.Integer, primary_key=True)
    qstn_id = db.Column(db.Integer)
    answer = db.Column(db.String, unique=True)
    votes = db.Column(db.Integer)
    accepted = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'login required'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'token is invalid'}), 401
        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/')
def index():
	return 'StackOverflow-Lite db endpoints'


@app.route('/auth/signup', methods=['POST'])
def add_user():

    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), username=data['username'], email=data['email'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'account created!'})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message': 'function requires admin'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message': 'The user has been promoted'})


@app.route('/user/demote/<public_id>', methods=['PUT'])
@token_required
def demote_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message': 'function requires admin'})
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'user not found'})
    if not user.admin:
        return jsonify({'message': 'user is already demoted'})

    user.admin = False
    db.session.commit()

    return jsonify({'message': 'user has been demoted'})


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message': 'function requires admin'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['username'] = user.username
    user_data['email'] = user.email
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user': user_data})


@app.route('/users', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message': 'function requires admin'})

    users = User.query.all()
    output = []
    for user in users: 
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['username'] = user.username
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)
    return jsonify({'users': output})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message': 'function requires admin'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'user has been deleted'})


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'WWW-Authenticate': 'Basic realm="login required!"'})

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('could not verify', 401, {'WWW-Authenticate': 'Basic realm="login required!"'})
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})
    return make_response('could not verify', 401, {'WWW-Authenticate': 'Basic realm="login required!"'})


@app.route('/questions', methods=['POST'])
@token_required
def add_question(current_user):
    data = request.get_json()
    new_question = Questions(topic=data['topic'], question=data['question'], user_id=current_user.id, votes=0)
    db.session.add(new_question)
    db.session.commit()
    return jsonify({'message': 'question added'})


@app.route('/questions', methods=['GET'])
def get_all_questions():
    questions = Questions.query.all()
    output = []
    for question in questions:
        items = {}
        items['id'] = question.id
        items['topic'] = question.topic
        items['question'] = question.question
        items['votes'] = question.votes
        items['user_id'] = question.user_id
        output.append(items)
    return jsonify({'questions': output})


@app.route('/questions/<question_id>', methods=['GET'])
def get_one_question(question_id):
    qstn = Questions.query.filter_by(id=question_id).first()
    if not qstn:
        return jsonify({'message': 'no question found!'})
    items = {}
    items['id'] = qstn.id
    items['topic'] = qstn.topic
    items['question'] = qstn.question
    items['votes'] = qstn.votes
    items['user_id'] = qstn.user_id
    return jsonify(items)


@app.route('/questions/<question_id>/upvote', methods=['PUT'])
def upvote_question(question_id):
    qstn = Questions.query.filter_by(id=question_id).first()
    if not qstn:
        return jsonify({'message': 'no qstn found'})
    qstn.votes += 1
    db.session.commit()
    return jsonify({'message': 'question upvoted'})


@app.route('/questions/<question_id>/downvote', methods=['PUT'])
@token_required
def downvote_question(current_user, question_id):
    qstn = Questions.query.filter_by(id=question_id).first()
    if not qstn:
        return jsonify({'message': 'no qstn found'})
    if qstn.votes == 0:
        return jsonify({'message': 'question has 0 votes'})
    qstn.votes -= 1
    db.session.commit()
    return jsonify({'message': 'question downvoted'})


@app.route('/questions/<question_id>', methods=['DELETE'])
@token_required
def delete_question(current_user, question_id):
    if not current_user.admin:
        return jsonify({'message': 'function requires admin'})

    qstn = Questions.query.filter_by(id=question_id).first()
    if not qstn:
        return jsonify({'message': 'question NOT found'})
    db.session.delete(qstn)
    db.session.commit()
    return jsonify({'message': 'question deleted'})


@app.route('/questions/<question_id>/answers', methods=['POST'])
@token_required
def post_answer(current_user, question_id):
    data = request.get_json()
    qstn = Questions.query.filter_by(id=question_id).first()
    if not qstn:
        return jsonify({'message': 'question NOT found'})
    new_answer = Answers(qstn_id=question_id, answer=data['answer'], votes=0, accepted=False, user_id=current_user.id)
    db.session.add(new_answer)
    db.session.commit()

    return jsonify({'message': 'answer posted'})


@app.route('/questions/<question_id>/answers', methods=['GET'])
def get_all_answers(question_id):

    qstn = Questions.query.filter_by(id=question_id).first()
    if not qstn:
        return jsonify({'message': 'answer NOT found'})

    answers = Answers.query.all()
    output = []
    for answer in answers:
        items = {}
        items['id'] = answer.id
        items['qstn_id'] = answer.qstn_id
        items['answer'] = answer.answer
        items['votes'] = answer.votes
        items['accepted'] = answer.accepted
        items['user_id'] = answer.user_id

        output.append(items)
    return jsonify({"answers": output})


@app.route('/questions/<question_id>/answers/<answer_id>')
def get_one_answer(question_id, answer_id):
    answer = Answers.query.filter_by(id=answer_id, qstn_id=question_id).first()
    if not answer:
        return jsonify({'message': 'answer NOT found!'})
    items = {}
    items['id'] = answer.id
    items['qstn_id'] = answer.qstn_id
    items['answer'] = answer.answer
    items['votes'] = answer.votes
    items['accepted'] = answer.accepted
    items['user_id'] = answer.user_id

    return jsonify(items)


@app.route('/questions/<question_id>/answers/<answer_id>', methods=['PUT'])
@token_required
def update_answer(current_user, question_id, answer_id):
    qstn_author = Questions.query.filter_by(id=question_id, user_id=current_user.id).first()
    if not qstn_author:
        return jsonify({'message': 'permission denied'})
    answer = Answers.query.filter_by(id=answer_id, qstn_id=question_id).first()
    if not answer:
        return jsonify({'message': 'answer NOT found!'})
    answer.accepted = True
    db.session.commit()
    return jsonify({'message': 'answer marked as accepted'})


if __name__ == '__main__':
    app.run(debug=True)
