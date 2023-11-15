from datetime import datetime

from sql.exts import db


class UserModel(db.Model):
    __tablename__ = "user"
    account = db.Column(db.String(50), nullable=False, primary_key=True, comment="用户账号(如学号等)", index=True)
    username = db.Column(db.String(50), nullable=False, comment="用户姓名")
    password = db.Column(db.String(256), nullable=False, comment="密码")
    random_salt = db.Column(db.String(256), nullable=False, comment="盐")
    sex = db.Column(db.String(20), nullable=True, comment="性别")
    height = db.Column(db.Float, nullable=True, comment="身高")
    weight = db.Column(db.Float, nullable=True, comment="体重")
    birthday = db.Column(db.DateTime, nullable=True, comment="生日")
    college = db.Column(db.String(50), nullable=False, comment="二级学院")
    classname = db.Column(db.String(50), nullable=False, comment="班级名称")
    account_state = db.Column(db.Integer, nullable=False, comment="账号状态")
    creator = db.Column(db.String(50), nullable=False, comment="创建人")
    create_time = db.Column(db.DateTime, nullable=False, comment="创建时间")
    update_by = db.Column(db.String(50), nullable=False, comment="更新人")
    update_time = db.Column(db.DateTime, nullable=False, comment="更新时间")

    sport_history = db.relationship("HistoryModel", backref="user", lazy=True)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_by_account(cls, account):
        return cls.query.filter_by(account=account).first()

    @classmethod
    def query_all_user(cls):
        return cls.query.all()


class HistoryModel(db.Model):
    __tablename__ = "sport_history"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True, comment="自增序号")
    account = db.Column(db.String(50), db.ForeignKey("user.account"), comment="用户账号")
    sport_name = db.Column(db.String(50), nullable=False, comment="运动名称")
    count = db.Column(db.Integer, nullable=False, comment="运动计数")
    sport_time = db.Column(db.Integer, nullable=False, comment="运动时间(秒)")
    start_time = db.Column(db.DateTime, nullable=False, comment="运动开始时间")

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def query_all_user(cls):
        return cls.query.all()

    @classmethod
    def query_all_by_account(cls, account):
        return cls.query.filter_by(account=account).all()

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


class AdminModel(db.Model):
    __tablename__ = "admin"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True, comment="自增序号")
    account = db.Column(db.String(50), nullable=False, comment="管理员账号")
    name = db.Column(db.String(50), nullable=False, comment="管理员姓名")
    password = db.Column(db.String(256), nullable=False, comment="密码")
    random_salt = db.Column(db.String(256), nullable=False, comment="盐")
    roles = db.Column(db.Integer, nullable=False, comment="管理员等级")
    account_state = db.Column(db.String(50), nullable=False, comment="账号是否可用")

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_by_adminAccount(cls, admin_account):
        return cls.query.filter_by(account=admin_account).first()

class LogModel(db.Model):
    __tablename__ = "log"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True, comment="自增ID")
    account = db.Column(db.String(50), comment="事件来源账号")
    type = db.Column(db.Integer, nullable=False, comment="事件类型")
    ip = db.Column(db.String(256), nullable=False, comment="事件来源IP")
    time = db.Column(db.DateTime, nullable=False, comment="事件来源时间")
    message = db.Column(db.String(256), nullable=False, comment="事件消息")

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def query_all_log(cls):
        return cls.query.all()
