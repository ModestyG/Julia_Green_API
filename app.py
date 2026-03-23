from datetime import timedelta
from functools import wraps
from flask import Flask, abort, redirect, jsonify, request, session, jsonify
from flasgger import Swagger, LazyJSONEncoder
from flasgger import swag_from
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required, create_refresh_token, get_jwt, verify_jwt_in_request
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.json_encoder = LazyJSONEncoder
app.config["JWT_SECRET_KEY"] = os.environ.get("PEOPLE_API_JWT_SECRET_KEY")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=30)
app.config["REFRESH_TOKEN_EXPIRES"] = timedelta(days=7)
jwt = JWTManager(app)

blocklisted_tokens = set()

def get_db_connection():
    try:
        return mysql.connector.connect(
            host='localhost',
            user='root',  
            password='',  
            database='people_api'
            
        )
    except mysql.connector.Error as err:
        abort(500)

swagger_template ={
    "swagger": "1.0",
    "openapi": "3.0.3",
    "uiversion": 3,
    "info": {
      "title": "People API",
      "description": "API Documentation for People Management",
      "termsOfService": "Terms of services",
      "version": "1.0",
      "host":"localhost:5000",
      "basePath":"http://localhost:5000",
      "license":{
        "name":"License of API",
        "url":"API license URL"
      }
              },
    "schemes": [
        "http",
        "https"
    ],
      }

swagger_config = {
    "headers": [
        ('Access-Control-Allow-Origin', '*'),
        ('Access-Control-Allow-Methods', "GET, POST"),
    ],
    "specs": [
        {
            "endpoint": '/docs/API',
            "route": '/docs/API.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/docs",
    
}


swagger = Swagger(app, template=swagger_template, config=swagger_config)


# Decorators for authentication

def auth_required(level=1):
    '''valid_jwt_required should not be used together with this decorator, it is already included in the implementation and will cause problems'''
    def auth_required_decorator(func):
        @wraps(func)
        @valid_jwt_required()
        def wrapper(*args, **kwargs):
            print("Checking if user has authorization level", level)
            user_id = get_jwt_identity()

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT auth_level FROM users WHERE id = %s", (user_id,))
            auth_level = cursor.fetchone()[0]
            print(f"Fetched auth level from database for user {user_id}: {auth_level}")
            cursor.close()
            conn.close()

            print(f"User auth level: {auth_level}")
            if not auth_level or not auth_level >= level:
                return jsonify({"error": "Forbidden"}), 403
            print(f"User {user_id} is authorized, proceeding...")
            return func(*args, **kwargs)
        return wrapper
    return auth_required_decorator

def valid_jwt_required(refresh=False):
    def valid_jwt_required_decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            print("Verifying JWT in request")
            verify_jwt_in_request(refresh=refresh)

            #Check if the token is revoked (i.e., if its jti is in the blocklist)
            print("Checking if token is revoked")
            jti = get_jwt().get('jti')
            if jti in blocklisted_tokens:
                print("Token is revoked, blocking access")
                return jsonify({"error": "Token revoked"}), 401
            print("Token is valid, allowing access")
            return func(*args, **kwargs)
        return wrapper
    return valid_jwt_required_decorator

@app.route('/', methods=['GET'])
def index(): 
    return redirect("/docs")

@swag_from("static/docs/login.yaml")
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"error": "Username and password are required fields"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    # It is important to check the password hash even if the user is not found to prevent timing attacks that could reveal valid usernames
    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid username or password"}), 401
    
    if "password" in user:
        del user["password"]

    access_token = create_access_token(identity=str(user["id"])) 
    refresh_token = create_refresh_token(identity=str(user["id"]))
    return jsonify({"message": "Login successful", "access_token": access_token, "refresh_token": refresh_token, "user": user}), 200

@swag_from("static/docs/register.yaml")
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"error": "Username and password are required fields"}), 400
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"error": "Username and password must be strings"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long"}), 400
    hashed_password = generate_password_hash(password)
    conn = get_db_connection()
    conn.autocommit=True
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
        cursor.close()
        conn.close()    
        return jsonify({"message": "User registered successfully"}), 201
    except mysql.connector.Error as err:
        cursor.close()
        conn.close() 
        print(f"Error: {err}")
        # Remember to come back here and look for a safer solution (maybe captcha if its possible or rate limiting) to prevent user enumeration attacks that could reveal valid usernames based on error messages
        # Sending a success message even on failiure would be the easiest and safest way of doing this but would compromise user experience and make it harder for legitimate users to know if they successfully registered or not 
        return jsonify({"error": "Username already exists"}), 409
    
@swag_from("static/docs/logout.yaml")
@app.route('/logout', methods=['POST'])
@valid_jwt_required()
def logout():
    jti = get_jwt().get('jti')
    blocklisted_tokens.add(jti)
    
    return jsonify({"message": "Logout successful"}), 200

@swag_from("static/docs/change_auth.yaml")
@app.route('/change_auth', methods=['PUT'])
@auth_required(level=2)
def change_auth():
    data = request.get_json()
    id = str(data.get("id", ""))
    new_auth_level = data.get("auth_level", "")

    if not id or new_auth_level is None:
        return jsonify({"error": "Id and new auth level are required"}), 400
    if not isinstance(new_auth_level, int) or new_auth_level < 0:
        return jsonify({"error": "Auth level must be a non-negative integer"}), 400

    conn = get_db_connection()
    conn.autocommit=True
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE id = %s", (id,))
    user = cursor.fetchone()
    if not user:
        cursor.close()
        conn.close()    
        return jsonify({"error": "User not found"}), 404

    try:
        cursor.execute("UPDATE users SET auth_level = %s WHERE id = %s", (new_auth_level, id))
        cursor.close()
        conn.close()    
        return jsonify({"message": f"Authorization level of user {id} successfully updated to {new_auth_level}"}), 200
    except Exception as e:
        print(f"Error for user {session['user']['id']} updating authorization of user {id}: {e}")
        return jsonify({"error": "Failed to update user authorization"}), 500

# People endpoints

@swag_from("static/docs/people.yaml")
@app.route("/people", methods=["GET"])
@valid_jwt_required()
def get_people():
    """
    Get all people or filter by name, age, or ID
    
     Optional query parameters:
     - name: filter by name
     - age: filter by age
     - id: filter by ID
    """
    name = request.args.get('name', "")
    age = request.args.get('age', "")
    id = request.args.get('id', "")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM people")
    people = cursor.fetchall()
    cursor.close()
    conn.close()

    if not name and not age and not id:
        return jsonify(people)
    
    people_list = []
    
    for person in people:
        if person["name"] != name and name:
            continue
        if str(person["age"]) != age and age:
            continue
        if str(person["id"]) != id and id:
            continue
        people_list.append(person)

    return jsonify(people_list)

@swag_from("static/docs/people_post.yaml")
@app.route("/people", methods=["POST"])
@auth_required(level=1)
def add_person():
    """
    Add a new person to the database.
    
    Request body parameters:
    - name: Name of the person (string)
    - age: Age of the person (integer)
    """
    data = request.get_json()
    name = data.get("name", "")
    age = data.get("age", "")

    if not name or not age:
        return jsonify({"error": "Name and age are required fields"}), 400
    
    if not isinstance(age, int):
        return jsonify({"error": "Age must be an integer"}), 400
    
    if age < 0:
        return jsonify({"error": "Age must be a non-negative integer"}), 400
    
    if not isinstance(name, str):
        return jsonify({"error": "Name must be a string"}), 400

    conn = get_db_connection()
    conn.autocommit=True
    cursor = conn.cursor(dictionary=True)
    cursor.execute("INSERT INTO people (name, age) VALUES (%s, %s)", (name, age))
    cursor.close()
    conn.close()    

    return jsonify({"message": "Person added successfully"}), 201

@swag_from("static/docs/people_{id}.yaml")
@app.route("/people/<id>", methods=["GET"])
@valid_jwt_required()
def get_person(id):
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM people WHERE id = %s", (id,))
    person = cursor.fetchone()
    cursor.close()
    conn.close()

    if person:
        return jsonify(person)
    return jsonify({"message": f"Person with id {id} not found"}), 404    

@swag_from("static/docs/people_{id}_put.yaml")
@app.route("/people/<id>", methods=["PUT"])
@auth_required(level=1)
def update_person(id):
    """
    Update an existing person's details.
    
    Path parameter:
    - id: ID of the person to update
    
    Possible request body parameters:
    - name: New name of the person (string)
    - age: New age of the person (integer)
    """
    data = request.get_json()

    name = data.get("name", "")
    age = data.get("age", "")

    update_fields = []
    values = []

    if name:
        if not isinstance(name, str):
            return jsonify({"error": "Name must be a string"}), 400
        
        update_fields.append("name = %s")
        values.append(name)
    if age:

        if not isinstance(age, int):
            return jsonify({"error": "Age must be an integer"}), 400
        if age < 0:
            return jsonify({"error": "Age must be a non-negative integer"}), 400
        
        age = str(age)
        update_fields.append("age = %s")
        values.append(age)
    if not update_fields:
        return jsonify({"error": "No valid fields to update"}), 400

    conn = get_db_connection()
    conn.autocommit=True
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM people WHERE id = %s", (id,))
    person = cursor.fetchone()

    if not person:
        cursor.close()
        conn.close()    
        return jsonify({"error": f"Person with id {id} not found"}), 404
    
    query = f"UPDATE people SET {', '.join(update_fields)} WHERE id = %s"
    values.append(id)
    try:
        cursor.execute(query, tuple(values)) 
        cursor.close()
        conn.close()    
        return jsonify({"message": "Person updated successfully"}), 200
    except Exception as e:
        print(f"Error updating person: {e}")
        cursor.close()
        conn.close()
        return jsonify({"error": f"Failed to update person"}), 500

@swag_from("static/docs/people_{id}_delete.yaml")
@app.route("/people/<id>", methods=["DELETE"])
@auth_required(level=1)  
def delete_person(id):
    conn = get_db_connection()
    conn.autocommit=True
    cursor = conn.cursor(dictionary=True)

    person = cursor.execute("SELECT * FROM people WHERE id = %s", (id,))
    if not person:
        cursor.close()
        conn.close()    
        return jsonify({"error": f"Person with id {id} not found"}), 404
    
    try:
        cursor.execute("DELETE FROM people WHERE id = %s", (id,)) 
        cursor.close()
        conn.close()    
        return jsonify({"message": "Person deleted successfully"}), 200
    except Exception as e:
        print(f"Error deleting person: {e}")
        return jsonify({"error": f"Failed to delete person"}), 500
    
@swag_from("static/docs/refresh.yaml")
@app.route("/refresh", methods=["POST"])
@valid_jwt_required(refresh=True)
def refresh():
    current_user_id = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user_id)
    return jsonify({"access_token": new_access_token}), 200



def sanitize_input(input):
    """
    Sanitize user input to prevent XSS attacks by escaping special characters.
    """
    new_input = escape(input)
    # More sanitization logic will be added here if I have the time
    return new_input

# Extra error handling

@app.errorhandler(500)
def internal_error(error):
    print(f"Internal server error: {error}")
    return jsonify({"error": f"Internal server error"}), 500

@app.errorhandler(404)
def not_found_error(error):
    print(f"Resource not found: {error}")
    return jsonify({"error": f"Resource not found"}), 404

@app.errorhandler(400)
def bad_request_error(error):
    print(f"Bad request: {error}")
    return jsonify({"error": f"Bad request"}), 400

@app.errorhandler(Exception)
def handle_http_exception(error):
    print(f"HTTP exception: {error}")
    return jsonify({"error": f"internal server error"}), 500

if __name__ == "__main__":
    app.run(debug=True)