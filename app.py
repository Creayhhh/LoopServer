import string
import random
from datetime import timedelta

from flask import Flask, make_response
from flask_jwt_extended import JWTManager
from flask_restful import Api
from flask_cors import CORS

from sql import sql_config
from sql.exts import db

import adminResources
import userResources

app = Flask(__name__)
api = Api(app)
jwt = JWTManager(app)

app.config.from_object(sql_config)
random_secretKey = ''.join(random.sample(string.ascii_letters + string.digits, 8))

app.config['PROPAGATE_EXCEPTIONS'] = True
app.config["SECRET_KEY"] = "loop_jwt_secret_key_pig_pig_pig" + random_secretKey
app.config["SESSION_COOKIE_SAMESITE"] = 'None'
app.config['SESSION_COOKIE_SECURE'] = True

app.config["JWT_SECRET_KEY"] = "loop_jwt_secret_key_pig_pig_pig"
app.config["JWT_TOKEN_LOCATION"] = ["headers"]
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=20)  # AccessToken 过期时间


CORS(app, supports_credentials=True, origins="http://localhost:4200")

db.init_app(app)
db.app = app
with app.app_context():
    db.create_all()

api.add_resource(adminResources.AdminLogin, '/admin/login')
api.add_resource(adminResources.AdminRegistration, '/admin/register')
api.add_resource(adminResources.AdminLogout, '/admin/logout')
api.add_resource(adminResources.CheckLogged, '/admin/checkLogged')
api.add_resource(adminResources.test, '/admin/test')
api.add_resource(adminResources.RegisterUser, '/admin/registerUser')
api.add_resource(adminResources.GetUsers, '/admin/getUsers')
api.add_resource(adminResources.GetUserAllInfo, '/admin/getUserAllInfo')
api.add_resource(adminResources.GetUsersSportHistory, '/admin/getUsersSportHistory')

api.add_resource(userResources.UserLogin, '/user/login')
api.add_resource(userResources.SubmitSportRecord, "/user/submit/record")
api.add_resource(userResources.QueryUserInfo, "/user/query/userinfo")
api.add_resource(userResources.QuerySportHistory, "/user/query/history")
api.add_resource(userResources.TokenRefresh, "/user/token/refresh")


@app.route('/')
def hello_world():
    return "hello"


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
