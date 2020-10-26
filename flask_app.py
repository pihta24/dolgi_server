import os
from json import JSONDecodeError
import secrets
from flask import Flask, json, request, render_template, abort
import requests
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
import sqlite3
import time
from email.mime.text import MIMEText
from re import *
from pprint import pprint
import requests
from urllib.parse import urljoin

# --------------------Настройки-------------------- #
db_path = 'data.db'  # путь к базе данных(str)
host = 'smtp.gmail.com'  # сервер smtp(str)
port = 587  # порт smtp(int)
email = 'superpochta24@gmail.com'  # адрес электронной почты(str)
e_password = '8s7inhs3'  # пароль электронной почты(str)
recapcha_secret = "6Ldsb-wUAAAAAMzbMeJcVKtEOCc0zR6pBzmGgVvI"
# --------------------Настройки-------------------- #

db = sqlite3.connect(db_path, check_same_thread=False)
cursor = db.cursor()

app = Flask(__name__)

smtpObj = smtplib.SMTP(host, port)

api_token = "f33a7bc6b7dea5b3f5f602de1748a306381a9c7d"
username = "dolgiapp"
pythonanywhere_host = "www.pythonanywhere.com"

api_base = "https://{pythonanywhere_host}/api/v0/user/{username}/".format(
    pythonanywhere_host=pythonanywhere_host,
    username=username,
)


def convert_user_db_list(db_list):
	out_list = []
	for i in db_list:
		out_list.append({'id': i[0], 'name': i[1], 'lastname': i[2], 'debt': i[3], 'curr': i[4], 'type': i[5]})
	return out_list


def log_exception(message, code):
	file = open("exception.log", "a")
	file.write("["+date_str() + " | " + time_str() + "] " + str(code) + " | " + str(message) + "\n")
	file.close()


def log_request(remote_ip, response, address):
	file = open("request.log", "a")
	file.write("[" + date_str() + " | " + time_str() + "] ip: " + str(remote_ip) + " response: " + str(response) + " address: " + str(address) + "\n")
	file.close()


def is_email(address):
	pattern = compile('(^|\s)[-a-z0-9_.]+@([-a-z0-9]+\.)+[a-z]{2,6}(\s|$)')
	is_valid = pattern.match(address)
	return is_valid


def mail(to_email, message):
	msg = MIMEText(message.encode('utf-8'), _charset='utf-8')
	smtpObj.sendmail(email, to_email, msg.as_string())


def date_str():
	r_date = str(time.localtime().tm_mday) + '.' + str(time.localtime().tm_mon) + '.' + str(time.localtime().tm_year)
	return r_date


def time_str():
	r_time = str(time.localtime().tm_hour) + ':' + str(time.localtime().tm_min) + ':' + str(time.localtime().tm_sec)
	return r_time


def check_user(data):
	try:
		cursor.execute("select password from users where nick = '%s' or email = '%s'" % (data["email_nick"], data["email_nick"]))
		users = cursor.fetchall()
		if len(users) == 0:
			return "{'response' : 'user not found'}"
		elif check_password_hash(users[0][0], data["password"]):
			return "{'response' : 'access granted'}"
		else:
			return "{'response' : 'access denied'}"
	except KeyError as e:
		return '{"response" : "parameter %s missed"}' % e
	except Exception as e:
		log_exception(e, "check_user")
		abort(500)
	except JSONDecodeError:
		return "{'response' : 'no parameters were passed'}"
	abort(500)


@app.route('/api/method/get_access_token', methods=['POST'])
def get_token():
	try:
		data = json.loads(request.data)
		checked = check_user(data)
		if checked == "{'response' : 'access granted'}":
			cursor.execute("select id, confirmed from users where nick = '%s' or email = '%s'" % (data["email_nick"], data["email_nick"]))
			id_conf = cursor.fetchall()[0]
			if id_conf[1] == 'true':
				id = id_conf[0]
				token = secrets.token_urlsafe()
				cursor.execute("insert into tokens values(%i,'%s')" % (id, generate_password_hash(token)))
				db.commit()
				log_request(request.remote_addr, "{'response' : '%i#%s'}" % (id, token), "get_access_token")
				return "{'response' : '%i#%s'}" % (id, token)
			else:
				return '{"response":"not confirmed"}'
		else:
			log_request(request.remote_addr, checked, "get_access_token")
			return checked
	except KeyError as e:
		log_request(request.remote_addr, '{"response" : "parameter %s missed"}' % e, "get_access_token")
		return '{"response" : "parameter %s missed"}' % e
	except Exception as e:
		log_exception(e, "get_access_token")
		abort(500)
	except JSONDecodeError:
		log_request(request.remote_addr, "{'response' : 'no parameters were passed'}", "get_access_token")
		return "{'response' : 'no parameters were passed'}"
	abort(500)


@app.route('/api/method/register_user', methods=['POST'])
def register_user():
	try:
		data = json.loads(request.data)
		cursor.execute("select nick from users where nick = '%s'" % data['nick'])
		nick = cursor.fetchall()
		cursor.execute("select email from users where email = '%s'" % data['email'])
		uemail = cursor.fetchall()
		if len(uemail) > 0:
			log_request(request.remote_addr, "{'response' : 'this email has been already taken'}", "register_user")
			return "{'response' : 'this email has been already taken'}"
		elif len(nick) > 0:
			log_request(request.remote_addr, "{'response' : 'this nick has been already taken'}", "register_user")
			return "{'response' : 'this nick has been already taken'}"
		elif not is_email(data['email']):
			log_request(request.remote_addr, "{'response' : 'not email'}", "register_user")
			return "{'response' : 'not email'}"
		elif len(data['nick']) < 3:
			log_request(request.remote_addr, "{'response' : 'nick length less than 3'}", "register_user")
			return "{'response' : 'nick length less than 3'}"
		else:
			code = secrets.token_urlsafe(10)
			cursor.execute("insert into users(name, last_name, password, nick, email, confirmed, code) values('%s', '%s', '%s', '%s', '%s', 'false', '%s')" % (data['name'], data['last_name'], generate_password_hash(data['password']), data['nick'], data['email'], code))
			db.commit()
			database = sqlite3.connect(data['nick']+"_database.db", check_same_thread=False)
			database.cursor().execute("CREATE TABLE debts(id INTEGER PRIMARY KEY AUTOINCREMENT, name VARCHAR, lastname VARCHAR, sum REAL, curr VARCHAR, type VARCHAR)")
			database.commit()
			database.close()
			try:
				smtpObj.connect(host, port)
				smtpObj.ehlo()
				smtpObj.starttls()
				smtpObj.ehlo()
				smtpObj.login(email, e_password)
				mail(data['email'], "Здравствуйте, %s!\nВаш код подтверждения: %s\nДля завершения регистрации подтвердите свой email по данной ссылке: https://dolgiapp.pythonanywhere.com/check_email" % (data['name'], code))
				smtpObj.quit()
			except Exception as e:
				log_exception(e, "mail")
			log_request(request.remote_addr, "ok", "register_user")
			return "{'response' : 'ok'}"
	except KeyError as e:
		log_request(request.remote_addr, '{"response" : "parameter %s missed"}' % e, "register_user")
		return '{"response" : "parameter %s missed"}' % e
	except Exception as e:
		log_exception(e, "register_user")
		abort(500)
	except JSONDecodeError:
		log_request(request.remote_addr, "{'response' : 'no parameters were passed'}", "register_user")
		return "{'response' : 'no parameters were passed'}"
	abort(500)


@app.route("/api/method/check_user", methods=['POST'])
def route_check_user():
	log_request(request.remote_addr, check_user(json.loads(request.data)), "check_user")
	return check_user(json.loads(request.data))


@app.route("/api/method/get_database", methods=['POST'])
def get_database():
	try:
		data = json.loads(request.data)
		if len(data['id_token'].split("#")) == 2:
			id = int(data['id_token'].split("#")[0])
			token = data['id_token'].split("#")[1]
		else:
			return "{'response' : 'not valid token'}"
		cursor.execute("select token from tokens where id = %i" % id)
		valid = False
		for i in cursor.fetchall():
			valid = check_password_hash(i[0], token)
			if valid:break
		if not valid:
			log_request(request.remote_addr, "{'response' : 'not valid token'}", "get_database")
			return "{'response' : 'not valid token'}"
		else:
			cursor.execute("select nick from users where id = %i" % id)
			database = sqlite3.connect(cursor.fetchall()[0][0] + "_database.db", check_same_thread=False)
			c = database.cursor()
			c.execute("select * from debts")
			response = "{'response':'ok', 'data':" + str(convert_user_db_list(c.fetchall()))+"}"
			response = response.replace(" ", "")
			database.close()
			log_request(request.remote_addr, response, "get_database")
			return response
	except KeyError as e:
		log_request(request.remote_addr, '{"response" : "parameter %s missed"}' % e, "get_database")
		return '{"response" : "parameter %s missed"}' % e
	except Exception as e:
		log_exception(e, "get_database")
		abort(500)
	except JSONDecodeError:
		log_request(request.remote_addr, "{'response' : 'no parameters were passed'}", "get_database")
		return "{'response' : 'no parameters were passed'}"
	abort(500)


@app.route("/api/method/get_one", methods=['POST'])
def get_one_from_database():
	try:
		data = json.loads(request.data)
		if len(data['id_token'].split("#")) == 2:
			id = int(data['id_token'].split("#")[0])
			token = data['id_token'].split("#")[1]
		else:
			return "{'response' : 'not valid token'}"
		cursor.execute("select token from tokens where id = %i" % id)
		valid = False
		for i in cursor.fetchall():
			valid = check_password_hash(i[0], token)
			if valid:break
		if not valid:
			log_request(request.remote_addr, "{'response' : 'not valid token'}", "get_one")
			return "{'response' : 'not valid token'}"
		else:
			cursor.execute("select nick from users where id = %i" % id)
			database = sqlite3.connect(cursor.fetchall()[0][0] + "_database.db", check_same_thread=False)
			c = database.cursor()
			c.execute("select * from debts where id = %i" % data['id'])
			response = "{'response': 'ok', 'data': " + str(convert_user_db_list(c.fetchall()))+"}"
			database.close()
			log_request(request.remote_addr, response, "get_one")
			return response
	except KeyError as e:
		log_request(request.remote_addr, '{"response" : "parameter %s missed"}' % e, "get_one")
		return '{"response" : "parameter %s missed"}' % e
	except Exception as e:
		log_exception(e, "get_database")
		abort(500)
	except JSONDecodeError:
		log_request(request.remote_addr, "{'response' : 'no parameters were passed'}", "get_one")
		return "{'response' : 'no parameters were passed'}"
	abort(500)


@app.route("/api/method/add_to_database", methods=['POST'])
def add_to_database():
	try:
		data = json.loads(request.data)
		if len(data['id_token'].split("#")) == 2:
			id = int(data['id_token'].split("#")[0])
			token = data['id_token'].split("#")[1]
		else:
			return "{'response' : 'not valid token'}"
		cursor.execute("select token from tokens where id = %i" % id)
		valid = False
		for i in cursor.fetchall():
			valid = check_password_hash(i[0], token)
			if valid: break
		if not valid:
			log_request(request.remote_addr, "{'response' : 'not valid token'}", "add_to_database")
			return "{'response' : 'not valid token'}"
		else:
			cursor.execute("select nick from users where id = %i" % id)
			database = sqlite3.connect(cursor.fetchall()[0][0] + "_database.db", check_same_thread=False)
			c = database.cursor()
			c.execute("insert into debts(name, lastname, sum, curr, type) values('%s', '%s', %f, '%s', '%s')" % (data['data']['name'], data['data']['lastname'], data['data']['debt'], data['data']['curr'], data['data']['type']))
			database.commit()
			database.close()
			log_request(request.remote_addr, "{'response' : 'ok'}", "add_to_database")
			return "{'response' : 'ok'}"
	except KeyError as e:
		log_request(request.remote_addr, '{"response" : "parameter %s missed"}' % e, "add_to_database")
		return '{"response" : "parameter %s missed"}' % e
	except Exception as e:
		log_exception(e, "add_to_database")
		abort(500)
	except JSONDecodeError:
		log_request(request.remote_addr, "{'response' : 'no parameters were passed'}", "add_to_database")
		return "{'response' : 'no parameters were passed'}"
	abort(500)


@app.route("/api/method/update_database", methods=['POST'])
def update_database():
	try:
		data = json.loads(request.data)
		if len(data['id_token'].split("#")) == 2:
			id = int(data['id_token'].split("#")[0])
			token = data['id_token'].split("#")[1]
		else:
			return "{'response' : 'not valid token'}"
		cursor.execute("select token from tokens where id = %i" % id)
		valid = False
		for i in cursor.fetchall():
			valid = check_password_hash(i[0], token)
			if valid: break
		if not valid:
			log_request(request.remote_addr, "{'response' : 'not valid token'}", "update_database")
			return "{'response' : 'not valid token'}"
		else:
			cursor.execute("select nick from users where id = %i" % id)
			database = sqlite3.connect(cursor.fetchall()[0][0] + "_database.db", check_same_thread=False)
			c = database.cursor()
			c.execute("update debts set name = '%s', lastname = '%s', sum = %f, curr = '%s', type = '%s' where id = %i" % (data['data']['name'], data['data']['lastname'], data['data']['debt'], data['data']['curr'], data['data']['type'], data['data']['id']))
			database.commit()
			database.close()
			log_request(request.remote_addr, "{'response' : 'ok'}", "update_database")
			return "{'response' : 'ok'}"
	except KeyError as e:
		log_request(request.remote_addr, '{"response" : "parameter %s missed"}' % e, "update_database")
		return '{"response" : "parameter %s missed"}' % e
	except Exception as e:
		log_exception(e, "update_database")
		abort(500)
	except JSONDecodeError:
		log_request(request.remote_addr, "{'response' : 'no parameters were passed'}", "update_database")
		return "{'response' : 'no parameters were passed'}"
	abort(500)


@app.route("/api/method/delete_from_database", methods=['POST'])
def delete_from_database():
	try:
		data = json.loads(request.data)
		if len(data['id_token'].split("#")) == 2:
			id = int(data['id_token'].split("#")[0])
			token = data['id_token'].split("#")[1]
		else:
			return "{'response' : 'not valid token'}"
		cursor.execute("select token from tokens where id = %i" % id)
		valid = False
		for i in cursor.fetchall():
			valid = check_password_hash(i[0], token)
			if valid: break
		if not valid:
			log_request(request.remote_addr, "{'response' : 'not valid token'}", "delete_from_database")
			return "{'response' : 'not valid token'}"
		else:
			cursor.execute("select nick from users where id = %i" % id)
			database = sqlite3.connect(cursor.fetchall()[0][0] + "_database.db", check_same_thread=False)
			c = database.cursor()
			c.execute("delete from debts where id = %i" % data['id'])
			database.commit()
			database.close()
			log_request(request.remote_addr, "{'response' : 'ok'}", "delete_from_database")
			return "{'response' : 'ok'}"
	except KeyError as e:
		log_request(request.remote_addr, '{"response" : "parameter %s missed"}' % e, "delete_from_database")
		return '{"response" : "parameter %s missed"}' % e
	except Exception as e:
		log_exception(e, "delete_from_database")
		abort(500)
	except JSONDecodeError:
		log_request(request.remote_addr, "{'response' : 'no parameters were passed'}", "delete_from_database")
		return "{'response' : 'no parameters were passed'}"
	abort(500)


@app.route("/api/method/delete_access_token", methods=['POST'])
def delete_access_token():
	try:
		data = json.loads(request.data)
		if len(data['id_token'].split("#")) == 2:
			id = int(data['id_token'].split("#")[0])
			token = data['id_token'].split("#")[1]
		else:
			log_request(request.remote_addr, "{'response' : 'not valid token'}", "delete_access_token")
			return "{'response' : 'not valid token'}"
		cursor.execute("select token from tokens where id = %i" % id)
		tokens = cursor.fetchall()
		valid = False
		index = 0
		for i in tokens:
			valid = check_password_hash(i[0], token)
			if valid: break
			index += 1
		if not valid:
			log_request(request.remote_addr, "{'response' : 'not valid token'}", "delete_access_token")
			return "{'response' : 'not valid token'}"
		else:
			cursor.execute("delete from tokens where token = '%s'" % tokens[index][0])
			db.commit()
			log_request(request.remote_addr, "{'response' : 'ok'}", "delete_access_token")
			return "{'response' : 'ok'}"
	except KeyError as e:
		log_request(request.remote_addr, '{"response" : "parameter %s missed"}' % e, "delete_access_token")
		return '{"response" : "parameter %s missed"}' % e
	except Exception as e:
		log_exception(e, "delete_from_database")
		abort(500)
	except JSONDecodeError:
		log_request(request.remote_addr, "{'response' : 'no parameters were passed'}", "delete_access_token")
		return "{'response' : 'no parameters were passed'}"
	abort(500)


@app.route("/api/method/delete_account", methods=['POST'])
def delete_account():
	try:
		data = json.loads(request.data)
		if len(data['id_token'].split("#")) == 2:
			id = int(data['id_token'].split("#")[0])
			token = data['id_token'].split("#")[1]
		else:
			log_request(request.remote_addr, "{'response' : 'not valid token'}", "delete_account")
			return "{'response' : 'not valid token'}"
		cursor.execute("select token from tokens where id = %i" % id)
		valid = False
		for i in cursor.fetchall():
			valid = check_password_hash(i[0], token)
			if valid: break
		if not valid:
			log_request(request.remote_addr, "{'response' : 'not valid token'}", "delete_account")
			return "{'response' : 'not valid token'}"
		else:
			cursor.execute("select password from users where id = %i" % id)
			if check_password_hash(cursor.fetchall()[0][0], data['password']):
				cursor.execute("select nick from users where id = %i" % id)
				path = cursor.fetchall()[0][0] + "_database.db"
				resp = requests.delete(
					urljoin(api_base, "files/path/home/{username}/{db}".format(username=username, db=path)),
					headers={"Authorization": "Token {api_token}".format(api_token=api_token)})
				cursor.execute("delete from tokens where id = %i" % id)
				cursor.execute("delete from users where id = %i" % id)
				db.commit()
				log_request(request.remote_addr, "{'response' : 'ok'}", "delete_account")
				return "{'response' : 'ok'}"
			else:
				log_request(request.remote_addr, "{'response' : 'wrong password'}", "delete_account")
				return "{'response' : 'wrong password'}"
	except KeyError as e:
		log_request(request.remote_addr, '{"response" : "parameter %s missed"}' % e, "delete_account")
		return '{"response" : "parameter %s missed"}' % e
	except Exception as e:
		log_exception(e, "delete_from_database")
		abort(500)
	except JSONDecodeError:
		log_request(request.remote_addr, "{'response' : 'no parameters were passed'}", "delete_account")
		return "{'response' : 'no parameters were passed'}"
	abort(500)


@app.route("/api/method/check_recapcha", methods=['POST', 'GET'])
def check_recapcha():
	try:
		data = request.form.get('g-recaptcha-response')
		response = requests.post("https://google.com/recaptcha/api/siteverify", data={'secret':recapcha_secret,'response':data,'remoteip':request.remote_addr})
		log_request(request.remote_addr, response.text+" | "+data, "check_recapcha")
		response_data = json.loads(response.text)
		cursor.execute("select confirmed, code from users where email = '%s'" % request.form.get('email'))
		confirmed = cursor.fetchall()
		if response_data['success']:
			if is_email(request.form.get('email')):
				if len(confirmed) == 0:
					user_response = "Данный email не зарегистрирован"
				elif confirmed[0][0] == "true":
					user_response = "Данный email уже подтвержден"
				else:
					if request.form.get('code') == confirmed[0][1]:
						cursor.execute("update users set confirmed = 'true' where email = '%s'" % request.form.get('email'))
						db.commit()
						user_response = "Email успешно подтвержден"
					else:
						user_response = "Неверный код"
			else:
				user_response = "Вы ввели не email"
		else:
			user_response = "Капча не пройдена"
		return render_template("email_check_answer.html", response=user_response)
	except KeyError as e:
		log_request(request.remote_addr, '{"response" : "parameter %s missed"}' % e, "check_recapcha")
		return '{"response" : "parameter %s missed"}' % e
	except Exception as e:
		log_exception(e, "check_recapcha")
		abort(500)
	except JSONDecodeError:
		log_request(request.remote_addr, "{'response' : 'no parameters were passed'}", "check_recapcha")
		return "{'response' : 'no parameters were passed'}"
	abort(500)


@app.route("/api/method/test", methods=['POST', 'GET'])
def test():
	try:
		print(request.get_data().decode('utf-8'))
		return json.dumps({'test':'test'}), 200
	except KeyError as e:
		log_request(request.remote_addr, '{"response" : "parameter %s missed"}' % e, "check_recapcha")
		return '{"response" : "parameter %s missed"}' % e
	except Exception as e:
		log_exception(e, "check_recapcha")
		abort(500)
	except JSONDecodeError:
		log_request(request.remote_addr, "{'response' : 'no parameters were passed'}", "check_recapcha")
		return "{'response' : 'no parameters were passed'}"
	abort(500)


@app.route("/check_email", methods=['GET'])
def check_email():
	try:
		log_request(request.remote_addr, " template 'email_check' rendered' ", "check_email")
		return render_template("email_check.html")
	except Exception as e:
		log_exception(e, "check_email")
		abort(500)
	abort(500)


@app.route('/login')
def login_form():
	return render_template("login.html")


@app.route('/api/method/')
def method_access_denied():
	return render_template("403.html"), 403


@app.errorhandler(404)
def page_not_found(e):
	log_exception(str(e), "404")
	return render_template('404.html'), 404


@app.errorhandler(405)
def method_not_allowed(e):
	log_exception(str(e), "405")
	return render_template('405.html'), 405


@app.errorhandler(500)
def internal_error(e):
	log_exception(str(e), "500")
	return render_template('500.html'), 500
