from flask import Flask,request,jsonify,make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash,check_password_hash
import jwt
import datetime
from functools import wraps

app=Flask(__name__)

app.config['SECRET_KEY']='QWERTYUIKJHGFDS'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'

db=SQLAlchemy(app)

class User(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    public_id=db.Column(db.String(50),unique=True)
    name=db.Column(db.String(80))
    password=db.Column(db.String(80))
    admin=db.Column(db.Boolean)

class Todo(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    text=db.Column(db.String(50))
    complete=db.Column(db.Boolean)
    user_id=db.Column(db.Integer)

def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token=None
        if 'x-access-token' in request.headers:
            token=request.headers['x-access-token']
        
        if not token:
            return jsonify({'message':'Token is missing!'}),401
        try:
            data=jwt.decode(token,app.config['SECRET_KEY'],algorithms=["HS256"],options=None)
            current_user=User.query.filter_by(public_id=data['public_id']).first()
        except Exception as e:
            print(e)
            return jsonify({'message':'Token is invalid'}),401  

        return f(current_user,*args,**kwargs)
    return decorated        


@app.route('/user',methods=['GET'])
@token_required
def get_all_user(current_user):

    users=User.query.all()
    output=[]

    for user in users:
        user_data={}
        user_data['public_id']=user.public_id
        user_data['name']=user.name
        user_data['password']=user.password
        user_data['admin']=user.admin
        output.append(user_data)
    return jsonify({'users':output})

@app.route('/user/<public_id>',methods=['GET'])
@token_required
def get_one_data(current_user,public_id):

    user=User.query.filter_by(public_id=public_id).first()
    print(type(user))
    print(user)
    if not user:
        return jsonify({'message':'No user found'})
    user_data={}
    user_data['public_id']=user.public_id
    user_data['name']=user.name
    user_data['password']=user.password
    user_data['admin']=user.admin 
    
    return {"user":user_data}

@app.route('/user',methods=['POST'])
@token_required
def create_user(current_user):

    if not current_user.admin:
        return jsonify({'message':"Can not Perform that Task"})

    data=request.get_json()
    hashed_password=generate_password_hash(data['password'],method='sha256')
    new_user=User(public_id=str(uuid.uuid4()),name=data['name'],password=hashed_password,admin=False)
    db.session.add(new_user)
    db.session.commit()
    print(data)
    return jsonify({'message':'New user created!'})

@app.route('/user/<public_id>',methods=['PUT'])
@token_required
def update_user(current_user,public_id):
    if not current_user.admin:
        return jsonify({'message':"Can not Perform that Task"})
    
    data=request.get_json
    user=User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message':'No user Found'})
    
    user.admin=True
    db.session.commit()
    return 'data Update'

@app.route('/user/<public_id>',methods=['DELETE'])
@token_required
def delete_user(current_user,public_id):
    if not current_user.admin:
        return jsonify({'message':"Can not Perform that Task"})
    
    user=User.query.filter_by(public_id=public_id).first()
    
    if not user:
        return jsonify({"message":"No user Found"})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message':'The user has been deleted !'})

@app.route('/login')
def login():
    auth=request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Colud not varify',401,{'WWW-Authenticate':'Basic realm="Login required!"'})
    
    user=User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Colud not varify',401,{'WWW-Authenticate':'Basic realm="Login required!"'})
    
    if check_password_hash(user.password,auth.password):
        token=jwt.encode({'public_id':user.public_id,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=30)},app.config['SECRET_KEY'])
        return jsonify({'token':token})
    
    return make_response('Colud not varify',401,{'WWW-Authenticate':'Basic realm="Login required!"'})


@app.route('/todo',methods=['GET'])
@token_required
def get_all_todo(current_user):

    todos=Todo.query.filter_by(user_id=current_user.id).all()
    output=[]

    for todo in todos:
        get_todo={}
        get_todo['id']=todo.id
        get_todo['text']=todo.text
        output.append(get_todo)
    return jsonify({'Todos':output})

@app.route('/todo/<todo_id>',methods=['GET'])
@token_required
def get_one_todo(current_user,todo_id):
    todo=Todo.query.filter_by(id=todo_id,user_id=current_user.id).first()

    if not todo:
        return jsonify({'message':'No Todo Found'})
    todo_data={}
    todo_data['id']=todo.id
    todo_data['text']=todo.text
    return jsonify(todo_data)

@app.route('/todo',methods=['POST'])
@token_required
def create_todo(current_user):
    data=request.get_json()

    todo=Todo(text=data['text'],complete=False,user_id=current_user.id)
    db.session.add(todo)
    db.session.commit()

    return jsonify({'message':'Todo has been insert'})

@app.route('/todo/<todo_id>',methods=['PUT'])
@token_required
def update_todo(current_user,todo_id):

    data=request.get_json()
    print(data)
    todo=Todo.query.filter_by(id=todo_id,user_id=current_user.id).first()

    if not todo:
        return jsonify({"message":"No Todo Found!"})
    todo.text=data['text']
    db.session.commit()
    return 'Todo Updated'

@app.route('/todo/<todo_id>',methods=['DELETE'])
@token_required
def delete_todo(current_user,todo_id):

    todo=Todo.query.filter_by(id=todo_id,user_id=current_user.id).first()

    if not todo:
        return jsonify({'message':'No Todo Found'})

    db.session.delete(todo)
    db.session.commit()

    return jsonify({"message":"The Todo Has been Deleted!"})

@app.route('/c',methods=['GET'])
def create_db():
    db.create_all()
    return "Data base crated"
if __name__=='__main__':
    app.run(debug=True)