import sqlite3

db_path = 'data.db'  # путь к базе данных(str)

db = sqlite3.connect(db_path, check_same_thread=False)
cursor = db.cursor()

#cursor.execute("drop table tokens")
#cursor.execute("drop table users")
#cursor.execute("CREATE TABLE tokens(id INTEGER, token VARCHAR(100))")
#cursor.execute("CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, name VARCHAR(100), last_name VARCHAR, password text, nick varchar(100), email varchar(100), confirmed varchar, code varchar)")
#db.commit()
#cursor.execute("alter table users add confirmed varchar")
#cursor.execute("update users set confirmed = 'false'")
#db.commit()
#cursor.execute("alter table users add code varchar")
#cursor.execute("update users set code = '0000'")
#db.commit()
cursor.execute("select * from users")
print(cursor.fetchall())
cursor.execute("select * from tokens")
print(cursor.fetchall())



