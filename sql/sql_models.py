from datetime import datetime

from sql.exts import db


class UserModel(db.Model):
    __tablename__ = "user"
    userid = db.Column(db.Integer, primary_key=True, autoincrement=True, comment="自增id")
    username = db.Column(db.String(50), nullable=False, comment="用户名")
    password = db.Column(db.String(256), nullable=False, comment="密码")
    nickname = db.Column(db.String(50), nullable=False, comment="用户昵称")
    sex = db.Column(db.String(20), nullable=False, comment="性别")
    height = db.Column(db.Integer, nullable=False, comment="身高")
    weight = db.Column(db.Integer, nullable=False, comment="体重")

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    @classmethod
    def query_all_user(cls):
        return cls.query.all()


class HistoryModel(db.Model):
    __tablename__ = "sport_history"
    num = db.Column(db.Integer, primary_key=True, autoincrement=True, comment="自增序号")
    username = db.Column(db.String(50), nullable=False, comment="用户名")
    sport_name = db.Column(db.String(50), nullable=False, comment="运动名称")
    count = db.Column(db.Integer, nullable=False, comment="运动计数")
    sport_time = db.Column(db.Integer, nullable=False, comment="运动时间(秒)")
    start_time = db.Column(db.DateTime, nullable=False, comment="运动开始时间")

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def query_all_by_username(cls, username):
        return cls.query.filter_by(username=username).all()

    @classmethod
    def query_select(cls, username, sport_name, start_time):
        if sport_name is not None and start_time is not None:
            return cls.query.filter(cls.username == username, cls.sport_name == sport_name,
                                    db.cast(cls.start_time, db.DATE) == db.cast(start_time, db.DATE)).all()
        elif start_time is None:
            return cls.query.filter_by(username=username, sport_name=sport_name).all()
        else:
            return cls.query.filter(cls.username == username,
                                    db.cast(cls.start_time, db.DATE) == db.cast(start_time, db.DATE)).all()
