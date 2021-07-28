from flask import make_response, request, json, jsonify
from flask_login import current_user, login_user, logout_user, login_required
from passlib.hash import sha256_crypt
from . import user_api_blueprint
from models import db, User, Confirmation
import requests
import random
from smsiran import SmsIR


# get all userrs
@user_api_blueprint.route('/api/users', methods=['GET'])
def get_users():
    data = []
    for row in User.query.all():
        data.append(row.to_json())

    response = jsonify(data)

    return response


# login a user
@user_api_blueprint.route('/api/user/login', methods=['POST'])
def post_login():
    mobile = request.json.get('mobile')
    user = User.query.filter_by(mobile=mobile).first()
    if user:
        if sha256_crypt.verify(str(request.json.get('password')), user.password):
            user.encode_api_key()
            db.session.commit()
            login_user(user)

            return make_response(jsonify({'message': 'Logged in', 'api_key': user.api_key}))

    return make_response(jsonify({'message': 'Not logged in'}), 401)


# check if a user exists
@user_api_blueprint.route('/api/user/exists', methods=['GET'])
def get_username():
    mobile = request.json.get('mobile')

    random_number = random.randint(1000, 9999)
    confirmation_t = Confirmation()
    confirmation_t.confirmation_code = random_number
    confirmation_t.mobile = mobile

    smsir = SmsIR("***", "****")
    smsir.otp(mobile, random_number)

    db.session.add(confirmation_t)
    db.session.commit()
    response = jsonify({'message': 'confirmation code sent to this mobile number'}), 200

    return response


# logout a user
@user_api_blueprint.route('/api/user/logout', methods=['POST'])
def post_logout():
    if current_user.is_authenticated:
        logout_user()
        return make_response(jsonify({'message': 'You are no longer logged in'}))

    return make_response(jsonify({'message': 'You are not logged in'}))


# get user detail
@login_required
@user_api_blueprint.route('/api/user', methods=['GET'])
def get_user():
    if current_user.is_authenticated:
        return make_response(jsonify({'result': current_user.to_json()}))

    return make_response(jsonify({'message': 'Not logged in'}), 401)


# check confirmation code
@user_api_blueprint.route('/api/user/confirmation/<mobile>', methods=['POST'])
def confirmation(mobile):
    confirmation_code = request.json.get('confirmation_code')
    res = Confirmation.query.filter_by(mobile=mobile).first()
    if confirmation_code == res.confirmation_code:
        Confirmation.query.filter_by(mobile=mobile).update(dict(is_confirmed=True))
        db.session.commit()
        return make_response(jsonify({'message': 'confirmed successfully'}), 200)
    return make_response(jsonify({'message': 'Not match'}), 401)


# register a user
@user_api_blueprint.route('/api/user/create', methods=['POST'])
def post_register():
    first_name = request.json.get('first_name')
    last_name = request.json.get('last_name')
    email = request.json.get('email')
    mobile = request.json.get('mobile')
    mellicode = request.json.get('mellicode')

    password = sha256_crypt.hash((str(request.json.get('password'))))
    d = Confirmation.query.filter_by(mobile=mobile).first()
    if d.is_confirmed:
        user = User()
        user.email = email
        user.first_name = first_name
        user.last_name = last_name
        user.password = password
        user.mobile = mobile
        user.mellicode = mellicode
        user.authenticated = True
        user.black_list()
        User.query.filter_by(mobile=mobile).update(
            dict(email=email, password=password, first_name=first_name, last_name=last_name, mellicode=mellicode))

        db.session.add(user)
        db.session.commit()

        response = jsonify({'message': 'User added', 'result': user.to_json()})

        return response
    return make_response(jsonify({'message': 'confirm your mobile first'}), 401)


# forget password
@user_api_blueprint.route('/api/user/forget-pass/<mobile>', methods=['POST'])
def forget_password(mobile):
    password = request.json.get('password')
    confirm_password = request.json.get('confirm_password')
    print(password, confirm_password)
    if password == confirm_password:
        User.query.filter_by(mobile=mobile).update(dict(password=sha256_crypt.hash(str(password))))
        db.session.commit()
        return jsonify({'message': 'password reset successfully'}), 200

    return jsonify({'message': 'password does not match'}), 401
