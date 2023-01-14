from flask import Flask
from flask_jwt_extended import JWTManager
from flask_restful import Api

from sql import sql_config
from sql.exts import db
import resources

app = Flask(__name__)
api = Api(app)
jwt = JWTManager(app)

app.config.from_object(sql_config)
app.config["JWT_SECRET_KEY"] = "loop_jwt_secret_key_pig_pig_pig"
app.config['PROPAGATE_EXCEPTIONS'] = True

db.init_app(app)
db.app = app
with app.app_context():
    db.create_all()

api.add_resource(resources.UserRegistration, '/registration')
api.add_resource(resources.UserLogin, '/login')
api.add_resource(resources.SubmitSportRecord, "/submit/record")
api.add_resource(resources.QueryUserInfo, "/query/userinfo")
api.add_resource(resources.QuerySportHistory, "/query/history")
api.add_resource(resources.TokenRefresh, "/token/refresh")


@app.route('/')
def hello_world():  # put application's code here
    return 'Hello World!'


if __name__ == '__main__':
    app.run()
