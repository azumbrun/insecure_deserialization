import pickle
import base64
from flask import Flask, request, render_template, make_response, redirect, url_for

# Initialize the Flask App
app = Flask(__name__)

# Define a simple User class
class UserProfile:
    def __init__(self, name, is_admin=False):
        self.name = name
        self.is_admin = is_admin

# Create the Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # For this demo, we'll use a hardcoded password
        if username == 'user' and password == 'password':
            # Create a user profile object
            user_obj = UserProfile(name=username, is_admin=False)
            
            # Serialize the object with pickle, then encode with base64
            pickled_obj = pickle.dumps(user_obj)
            encoded_cookie = base64.b64encode(pickled_obj)
            
            # Create a response and set the cookie
            resp = make_response(redirect(url_for('home')))
            resp.set_cookie('user_profile', encoded_cookie.decode('utf-8'))
            return resp

        return "Invalid login", 401
    
    # If GET request, just show the login form
    return render_template('login.html')

# Create the Home (Protected) Route
@app.route('/')
def home():
    # Get the cookie from the request
    encoded_cookie = request.cookies.get('user_profile')
    
    if encoded_cookie:
        try:
            # Decode from base64 first
            pickled_obj = base64.b64decode(encoded_cookie.encode('utf-8'))
            
            # DANGER: This is the vulnerable step.
            # In a real application, NEVER use pickle.loads() on untrusted data.
            user_obj = pickle.loads(pickled_obj)

            return render_template('home.html', user=user_obj)
        except Exception as e:
            return f"An error occurred: {e}", 500
            
    return redirect(url_for('login'))

# 5. Run the App
if __name__ == '__main__':
    app.run(debug=True)

