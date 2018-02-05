from flask import Flask,session,request,jsonify,make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import uuid
import jwt
import datetime
from functools import wraps
from flaskext.mysql import MySQL
from flask_cors import CORS



app = Flask(__name__)
app.config['SECRET_KEY'] = "richgem2326"
mysql = MySQL()
CORS(app)

#Configuration for using MySQL
app.config['MYSQL_DATABASE_USER'] = 'root'
app.config['MYSQL_DATABASE_PASSWORD'] = ''
app.config['MYSQL_DATABASE_DB'] = 'flask_auth'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
app.config['MYSQL_DATABASE_CURSORCLASS']='DictCursor'

mysql.init_app(app)

# Wrap for checking auth token exists or not
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        #print token

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try:
        	
            data = jwt.decode(token, app.config['SECRET_KEY'])
            conn = mysql.connect()
            cursor = conn.cursor()
            #print data
            res = cursor.execute('select * from user where public_id =%s',[data['public_id']])


            #current_user = User.query.filter_by(public_id=data['public_id']).first()
            current_user = cursor.fetchone()
            conn.close()
        except Exception as e:
            
            return jsonify({'message' : 'Token is invalid!'}), 401
            

        return f(current_user, *args, **kwargs)

    return decorated





#viewing all the users
@app.route("/user")
@token_required
def get_users(current_user):
    if not current_user[4]:
        return jsonify({'message' : 'Cannot perform that function!'})

    list_of_users =[]
    conn = mysql.connect()
    cursor= conn.cursor()

    result = cursor.execute('select * from user')

    if result==0:
        return jsonify({"No users found Admin!"}),201
    for user in cursor.fetchall():
        newUser={}
        newUser['name'] = user[2]
        newUser['public_id'] = user[1]
        list_of_users.append(newUser)
    return jsonify({"users":list_of_users}),200







# Creating the user
@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user[4]:
         return jsonify({'message' : 'Cannot perform that function!'})

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    #mysql commands to put the user in the database
    conn = mysql.connect()
    cursor = conn.cursor()

    name = data['name']
    public_id = str(uuid.uuid4())
    admin = False
    password = generate_password_hash(data['password'])


    cursor.execute('insert into user(name,password,public_id,admin) values (%s,%s,%s,%s)',(name,password,public_id,admin))
    conn.commit()

    return jsonify({'message' : 'New user created!'})

#User login




# Promoting the user to the admin role
@app.route("/user/<public_id>", methods=["PUT"])
@token_required
def make_admin(current_user,public_id):
	if not current_user[4]:
		return jsonify({'message' : 'Cannot perform that function!'})
	conn = mysql.connect()
	cursor = conn.cursor()
	cursor.execute('update user set admin=true where public_id=%s',[public_id])
	conn.commit()
	return jsonify({'message' : 'The user has been promoted!'})



@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    conn = mysql.connect()
    cursor = conn.cursor()

    resp = cursor.execute('select * from user where name =%s',[auth.username])


    if resp<=0:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = cursor.fetchone()

    if check_password_hash(user[3], auth.password):
        token = jwt.encode({'public_id' : user[1], 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})





#Deleting a user
@app.route("/user/<public_id>",methods=["DELETE"])
@token_required
def delete_user(current_user,public_id):
    if not current_user[4]:
        return jsonify({'message' : 'Cannot perform that function!'})
    conn = mysql.connect()
    cursor = conn.cursor()
    res = cursor.execute('select * from user where public_id=%s',[public_id])
    if res == 0:
        return jsonify({"message":" User not found!"}), 401
    else:
        cursor.execute("delete from user where public_id = %s",[public_id])
        conn.commit();
        conn.close();
        return jsonify({"message":"The user has been deleted!"}),200





if __name__ == '__main__':
    app.run(debug=True)