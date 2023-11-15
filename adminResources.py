from flask import jsonify, request, session
from flask_restful import Resource, reqparse
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt, \
    set_access_cookies, set_refresh_cookies
import datetime
from sql.sql_models import AdminModel, UserModel, HistoryModel
import utils
import pytz
from werkzeug.security import generate_password_hash, check_password_hash
import global_config


class AdminLogin(Resource):
    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument('account', type=str, required=True)
        self.parser.add_argument('password', type=str, required=True)
        super(AdminLogin, self).__init__()

    def post(self):
        args = self.parser.parse_args()
        if args["account"] == "" or args["password"] == "":
            return jsonify({'state_code': '101', 'message': 'Key value error'})

        admin_info = AdminModel.find_by_adminAccount(args['account'])
        if admin_info is None:
            return jsonify({'state_code': '301', 'message': 'Account not exists'})

        print(args['password'])
        print(admin_info.random_salt)
        print(utils.sha256Encryption(args['password'], admin_info.random_salt))
        if admin_info.password == utils.sha256Encryption(args['password'], admin_info.random_salt):
            if admin_info.account_state == -1:
                return jsonify({'state_code': '303', 'message': 'Account not active'})

            if admin_info.account_state == -2:
                return jsonify({'state_code': '304', 'message': 'Account has been cancelled'})
            
            response = jsonify(
                {
                    'state_code': '0',
                    'message': 'Login Success',
                    'data': {
                        'account': admin_info.account,
                        'name': admin_info.name,
                        'roles': admin_info.roles
                    }
                }
            )

            session["account"] = admin_info.account
            session["name"] = admin_info.name
            session["finalOperation"] = datetime.datetime.now(tz=pytz.UTC)

            return response

        else:
            return jsonify({'state_code': '302', 'message': 'Password error'})


class AdminRegistration(Resource):
    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument('account', type=str, required=True)
        self.parser.add_argument('name', type=str, required=True)
        self.parser.add_argument('password', type=str, required=True)
        self.parser.add_argument('roles', type=str, required=True)
        super(AdminRegistration, self).__init__()

    def post(self):
        args = self.parser.parse_args()
        if (args["account"] == "") or (args["name"] == "") or (args["password"] == "") or \
                (args["roles"] == ""):
            return jsonify({'state_code': '-1', 'message': 'Key value error'})

        if AdminModel.find_by_adminAccount(args['account']):
            return jsonify({'state_code': '201', 'message': 'Admin {} already exists'.format(args['username'])})

        salt = utils.random_salt()
        new_admin = AdminModel(
            account=args['account'],
            name=args['name'],
            password=utils.sha256Encryption(args['password'], salt),
            random_salt=salt,
            roles=args['roles'],
            account_state="normal"
        )

        try:
            new_admin.save_to_db()
            return jsonify({'state_code': '0', 'message': 'Admin registration success'})


        except Exception as e:
            print(e)
            return jsonify({'state_code': '-1', 'message': 'Something went wrong'})


class AdminLogout(Resource):
    def delete(self):
        session.pop('account', None)
        session.pop('name', None)
        session.pop('finalOperation', None)
        return jsonify({'state_code': '0', 'message': 'Logout success'})


class CheckLogged(Resource):
    def post(self):
        print(session)
        if 'account' in session:
            if (datetime.datetime.now(tz=pytz.UTC) - session['finalOperation']).total_seconds() > global_config.adminSessionTimeoutTime:
                return jsonify({'state_code': '102', 'message': 'Login has expired'})
            else:
                session["finalOperation"] = datetime.datetime.now(tz=pytz.UTC)
                return jsonify({'state_code': '101', 'message': 'Logged in'})
        else:
            return jsonify({'state_code': '100', 'message': 'Not log in'})


class RegisterUser(Resource):
    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument('account', type=str, required=True)
        self.parser.add_argument('username', type=str, required=True)
        self.parser.add_argument('password', type=str, required=True)
        self.parser.add_argument('college', type=str, required=True)
        self.parser.add_argument('classname', type=str, required=True)
        self.parser.add_argument('sex', type=str, required=False)
        self.parser.add_argument('height', type=str, required=False)
        self.parser.add_argument('weight', type=str, required=False)
        self.parser.add_argument('birthday', type=str, required=False)
        super(RegisterUser, self).__init__()

    def post(self):
        if 'account' not in session:
            return jsonify({'state_code': '100', 'message': 'Not log in'})

        if (datetime.datetime.now(tz=pytz.UTC) - session['finalOperation']).total_seconds() > global_config.adminSessionTimeoutTime:
            return jsonify({'state_code': '102', 'message': 'Login has expired'})

        session["finalOperation"] = datetime.datetime.now(tz=pytz.UTC)

        args = self.parser.parse_args()
        if (args["account"] == "") or (args["username"] == "") or (args["password"] == "") or (args["college"] == "") or (args["classname"] == ""):
            return jsonify({'state_code': '-1', 'message': 'Key value error'})

        find_user = UserModel.find_by_account(args['account'])
        if find_user:
            if find_user.account_state != 3:
                return jsonify({'state_code': '201', 'message': 'User {} already exists'.format(args['username'])})

        salt = utils.random_salt()
        time = datetime.datetime.now().strftime('%Y-%m-%d,%H:%M:%S')
        print(time)
        new_user = UserModel(
            account=args['account'],
            username=args['username'],
            password=utils.sha256Encryption(args['password'], salt),
            random_salt=salt,
            college=args['college'],
            classname=args['classname'],
            sex=args['sex'],
            height=args['height'],
            weight=args['weight'],
            birthday=args['birthday'],
            account_state=1,
            creator=session['name'],
            update_by=session['name'],
            create_time=time,
            update_time=time
        )
        print(time)
        try:
            new_user.save_to_db()
            return jsonify({'state_code': '0', 'message': 'User {} registration success'.format(args['account'])})
        except Exception as e:
            print(e)
            return jsonify({'state_code': '-1', 'message': 'Something went wrong'})


class GetUsers(Resource):
    def post(self):
        if 'account' not in session:
            return jsonify({'state_code': '100', 'message': 'Not log in'})

        if (datetime.datetime.now(tz=pytz.UTC) - session['finalOperation']).total_seconds() > global_config.adminSessionTimeoutTime:
            return jsonify({'state_code': '102', 'message': 'Login has expired'})
        try:
            session["finalOperation"] = datetime.datetime.now(tz=pytz.UTC)
            users_object = UserModel.query_all_user()
            users_list = []
            for user in users_object:
                user_data = {
                    "account": user.account,
                    "username": user.username,
                    "college": user.college,
                    "classname": user.classname,
                    "account_state": user.account_state
                }
                users_list.append(user_data)
            return {'state_code': 0, 'message': 'Query all user success', 'data': users_list}

        except:
            return {'state_code': -2, 'message': 'Something went wrong'}


class GetUserAllInfo(Resource):
    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument('account', type=str, required=True)
        super(GetUserAllInfo, self).__init__()

    def post(self):
        if 'account' not in session:
            return jsonify({'state_code': '100', 'message': 'Not log in'})

        if (datetime.datetime.now(tz=pytz.UTC) - session['finalOperation']).total_seconds() > global_config.adminSessionTimeoutTime:
            return jsonify({'state_code': '102', 'message': 'Login has expired'})

        args = self.parser.parse_args()
        session["finalOperation"] = datetime.datetime.now(tz=pytz.UTC)

        try:
            query_result = UserModel.find_by_account(args['account'])
            if query_result:
                user = {
                    'account': query_result.account,
                    'username': query_result.username,
                    'sex': query_result.sex,
                    'height': query_result.height,
                    'weight': query_result.weight,
                    'birthday': datetime.datetime.strftime(query_result.birthday, "%Y-%m-%d"),
                    'college': query_result.college,
                    'classname': query_result.classname,
                    'account_state': query_result.account_state,
                    'creator': query_result.creator,
                    'create_time': datetime.datetime.strftime(query_result.create_time, "%Y-%m-%d %H:%M:%S"),
                    'update_by': query_result.update_by,
                    'update_time': datetime.datetime.strftime(query_result.update_time, "%Y-%m-%d %H:%M:%S")
                }
                return jsonify({'state_code': 0, 'message': 'Query user success', 'data': user})

            else:
                return jsonify({'state_code': 202, 'message': 'User not exists'})
        except Exception as e:
            print(e)
            return {'state_code': -2, 'message': 'Something went wrong'}


class GetUsersSportHistory(Resource):
    def post(self):
        if 'account' not in session:
            return jsonify({'state_code': '100', 'message': 'Not log in'})

        if (datetime.datetime.now(tz=pytz.UTC) - session['finalOperation']).total_seconds() > global_config.adminSessionTimeoutTime:
            return jsonify({'state_code': '102', 'message': 'Login has expired'})
        try:
            data_object = HistoryModel.query_all_user()
            session["finalOperation"] = datetime.datetime.now(tz=pytz.UTC)
            data_list = []
            for data in data_object:
                data_temp = {
                    "account": data.account,
                    "username": data.username,
                    "sport_name": data.sport_name,
                    "count": data.count,
                    "sport_time": data.sport_time,
                    "start_time": datetime.datetime.strftime(data.start_time, "%Y-%m-%d %H:%M:%S")
                }
                data_list.append(data_temp)
            return {'state_code': 0, 'message': 'Query all user success', 'data': data_list}

        except Exception as e:
            print(e)
            return {'state_code': -2, 'message': 'Something went wrong'}


class test(Resource):
    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument('account', type=str, required=True)
        self.parser.add_argument('username', type=str, required=True)
        self.parser.add_argument('password', type=str, required=True)
        self.parser.add_argument('college', type=str, required=True)
        self.parser.add_argument('classname', type=str, required=True)
        self.parser.add_argument('sex', type=str, required=False)
        self.parser.add_argument('height', type=str, required=False)
        self.parser.add_argument('weight', type=str, required=False)
        self.parser.add_argument('birthday', type=str, required=False)
        super(test, self).__init__()

    def post(self):
        args = self.parser.parse_args()
        print(args)
        return jsonify({"state_code": "0"})
