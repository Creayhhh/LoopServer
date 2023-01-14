from flask_restful import Resource, reqparse
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt
from sql.sql_models import UserModel, HistoryModel
import datetime

parser = reqparse.RequestParser()
parser.add_argument('username', help='This field cannot be blank', required=True, nullable=False)

parser.add_argument('password', help='Key value error', required=False, nullable=True)
parser.add_argument('nickname', help='Key value error', required=False, nullable=True)
parser.add_argument('sex', help='Key value error', required=False, nullable=True)
parser.add_argument('height', help='Key value error', required=False, nullable=True)
parser.add_argument('weight', help='Key value error', required=False, nullable=True)

parser.add_argument('sport_name', help='Key value error', required=False, nullable=True)
parser.add_argument('count', help='Key value error', required=False, nullable=True)
parser.add_argument('sport_time', help='Key value error', required=False, nullable=True)
parser.add_argument('start_time', help='Key value error', required=False, nullable=True)


class UserRegistration(Resource):
    def post(self):
        post_data = parser.parse_args()
        if UserModel.find_by_username(post_data['username']):
            return {'state': 0, 'message': 'User {} already exists'.format(post_data['username'])}

        if ("password" not in post_data) or ("nickname" not in post_data) or ("sex" not in post_data) or (
                "height" not in post_data) \
                or ("weight" not in post_data):
            return {'state': -1, 'message': 'Key error'}

        if (post_data["password"] is None) or (post_data["nickname"] is None) or (post_data["sex"] is None) or \
                (post_data["height"] is None) or (post_data["weight"] is None):
            return {'state': -1, 'message': 'Key value error'}

        new_user = UserModel(
            username=post_data['username'],
            password=post_data['password'],
            nickname=post_data['nickname'],
            sex=post_data['sex'],
            height=int(post_data['height']),
            weight=int(post_data['weight'])
        )

        try:
            new_user.save_to_db()
            return {'state': 1, 'message': 'User registration success'}

        except:
            return {'state': -2, 'message': 'Something went wrong'}


class UserLogin(Resource):
    def post(self):
        post_data = parser.parse_args()
        if post_data["password"] is None:
            return {'state': -1, 'message': 'Key value error'}

        user = UserModel.find_by_username(post_data['username'])
        if user is None:
            return {'state': 0, 'message': 'User not exists'}

        if user.password == post_data["password"]:
            access_token = create_access_token(identity=post_data['username'])
            refresh_token = create_refresh_token(identity=post_data['username'])
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
        username = get_jwt_identity()
        user = UserModel.find_by_username(username)
        if user is None:
            return {'state': 0, 'message': 'User not exists'}

        user_info = {
            "username": user.username,
            "nickname": user.nickname,
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
    @jwt_required()
    def post(self):
        post_data = parser.parse_args()
        username = get_jwt_identity()
        if (post_data["sport_name"] is None) or (post_data["count"] is None) or \
                (post_data["sport_time"] is None) or (post_data["start_time"] is None):
            return {'state': -1, 'message': 'Key value error'}

        new_history = HistoryModel(
            username=username,
            sport_name=post_data["sport_name"],
            count=int(post_data["count"]),
            sport_time=int(post_data["sport_time"]),
            start_time=post_data["start_time"]
        )

        try:
            new_history.save_to_db()
            return {'state': 1, 'message': 'Save sport record success'}
        except:
            return {'state': -2, 'message': 'Something went wrong'}


class QuerySportHistory(Resource):
    @jwt_required()
    def post(self):
        post_data = parser.parse_args()
        username = get_jwt_identity()
        try:
            if post_data["sport_name"] is None and post_data["start_time"] is None:
                sport_history_object = HistoryModel.query_all_by_username(username)
            else:
                sport_history_object = HistoryModel.query_select(username, post_data["sport_name"], post_data["start_time"])

            sport_history_list = []
            for sport_history in sport_history_object:
                sport_history_data = {
                    "username": sport_history.username,
                    "sport_name": sport_history.sport_name,
                    "count": sport_history.count,
                    "sport_time": sport_history.sport_time,
                    "start_time": datetime.datetime.strftime(sport_history.start_time, "%Y-%m-%d %H:%M:%S")
                }
                sport_history_list.append(sport_history_data)

            return {'state': 1, 'message': 'Query sport history success', 'sport_history': sport_history_list}
        except:
            return {'state': -2, 'message': 'Something went wrong'}


class QueryAllUser(Resource):
    @jwt_required()
    def post(self):
        try:
            users_object = UserModel.query_all_user()
            users_list = []
            for user in users_object:
                user_data = {
                    "username": user.username,
                    "nickname": user.nickname,
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
