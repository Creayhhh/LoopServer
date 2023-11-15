from flask_restful import Resource, reqparse
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt
from sql.sql_models import UserModel, HistoryModel
import datetime
from hashlib import sha256


class UserLogin(Resource):
    def __init__(self) -> None:
        self.parser = reqparse.RequestParser()
        self.parser.add_argument('account', help='This field cannot be blank', required=True, nullable=True)
        self.parser.add_argument('password', help='Key value error', required=True, nullable=True)
        super(UserLogin, self).__init__()

    def post(self):
        post_data = self.parser.parse_args()
        if post_data["password"] is None:
            return {'state': -1, 'message': 'Key value error'}

        user = UserModel.find_by_account(post_data['account'])
        if user is None:
            return {'state': 0, 'message': 'User not exists'}

        if user.password == sha256((post_data["password"] + user.random_salt).encode()).hexdigest():
            access_token = create_access_token(identity=post_data['account'])
            refresh_token = create_refresh_token(identity=post_data['account'])
            return {
                'state': 1,
                'message': 'Login success',
                "token": {
                    "access_token": access_token,
                    "refresh_token": refresh_token
                }
            }
        else:
            return {'state': -2, 'message': 'Password error'}


class QueryUserInfo(Resource):
    @jwt_required()
    def post(self):
        account = get_jwt_identity()
        user = UserModel.find_by_account(account)
        if user is None:
            return {'state': 0, 'message': 'User not exists'}

        user_info = {
            "account": user.account,
            "username": user.username,
            "sex": user.sex,
            "height": user.height,
            "weight": user.weight
        }
        return {
            'state': 1,
            'message': 'Query success',
            'user_info': user_info
        }


class SubmitSportRecord(Resource):
    def __init__(self) -> None:
        self.parser = reqparse.RequestParser()

        self.parser.add_argument('username', help='Key value error', required=True, nullable=True)
        self.parser.add_argument('sport_name', help='Key value error', required=True, nullable=True)
        self.parser.add_argument('count', help='Key value error', required=True, nullable=True)
        self.parser.add_argument('sport_time', help='Key value error', required=True, nullable=True)
        self.parser.add_argument('start_time', help='Key value error', required=True, nullable=True)

        super(SubmitSportRecord, self).__init__()

    @jwt_required()
    def post(self):
        post_data = self.parser.parse_args()
        account = get_jwt_identity()
        if (post_data["sport_name"] is None) or (post_data["count"] is None) or \
                (post_data["sport_time"] is None) or (post_data["start_time"] is None):
            return {'state': -1, 'message': 'Key value error'}

        new_history = HistoryModel(
            account=account,
            username=post_data["username"],
            sport_name=post_data["sport_name"],
            count=int(post_data["count"]),
            sport_time=int(post_data["sport_time"]),
            start_time=post_data["start_time"]
        )

        try:
            new_history.save_to_db()
            return {'state': 1, 'message': 'Save sport record success'}
        except Exception as e:
            print(e)
            return {'state': -2, 'message': 'Something went wrong'}


class QuerySportHistory(Resource):
    def __init__(self):
        self.parser = reqparse.RequestParser()

        self.parser.add_argument('sport_name', help='Key value error', nullable=True)
        self.parser.add_argument('count', help='Key value error', nullable=True)
        self.parser.add_argument('sport_time', help='Key value error', nullable=True)
        self.parser.add_argument('start_time', help='Key value error', nullable=True)

        super(QuerySportHistory, self).__init__()

    @jwt_required()
    def post(self):
        post_data = self.parser.parse_args()
        account = get_jwt_identity()
        try:
            if post_data["sport_name"] is None and post_data["start_time"] is None:
                sport_history_object = HistoryModel.query_all_by_account(account)
            else:
                sport_history_object = HistoryModel.query_select(account, post_data["sport_name"],
                                                                 post_data["start_time"])

            sport_history_list = []
            for sport_history in sport_history_object:
                sport_history_data = {
                    "account": sport_history.account,
                    "sport_name": sport_history.sport_name,
                    "count": sport_history.count,
                    "sport_time": sport_history.sport_time,
                    "start_time": datetime.datetime.strftime(sport_history.start_time, "%Y-%m-%d %H:%M:%S")
                }
                sport_history_list.append(sport_history_data)

            return {'state': 1, 'message': 'Query sport history success', 'sport_history': sport_history_list}
        except Exception as e:
            print(e)
            return {'state': -2, 'message': 'Something went wrong'}


class QueryAllUser(Resource):
    @jwt_required()
    def post(self):
        try:
            users_object = UserModel.query_all_user()
            users_list = []
            for user in users_object:
                user_data = {
                    "account": user.account,
                    "username": user.username,
                    "sex": user.sex,
                    "height": user.height,
                    "weight": user.weight
                }
                users_list.append(user_data)
            return {'state': 1, 'message': 'Query all user success', 'users': users_list}
        except:
            return {'state': -2, 'message': 'Something went wrong'}


class VerifyJWT(Resource):
    @jwt_required()
    def post(self):
        try:
            print(get_jwt_identity())
            return {"message": "Verify success"}
        except:
            return {"message": "Token error"}


class TokenRefresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user)
        return {'access_token': access_token}
