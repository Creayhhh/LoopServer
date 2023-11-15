HOST = 'your database ip address'
PORT = 'your database port'
DATABASE = 'loop'
USERNAME = 'loop'
PASSWORD = 'aHF2RHwDC83DB5em'

DB_URI = "mysql+pymysql://{username}:{password}@{host}:{port}/{db}?charset=utf8".format(username=USERNAME,
                                                                                        password=PASSWORD, host=HOST,
                                                                                        port=PORT, db=DATABASE)

SQLALCHEMY_DATABASE_URI = DB_URI
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_ECHO = True
