import pickle
import base64
import hmac
import hashlib
import io
from flask import Flask, request, render_template, make_response, redirect, url_for

# Initialize the Flask App
app = Flask(__name__)

# SECURITY CONFIGURATION
# In a real app, keep this secret
SECRET_KEY = b'super_secret_project2_key' 

# Define the User class
class UserProfile:
    def __init__(self, name, is_admin=False):
        self.name = name
        self.is_admin = is_admin

# PREVENTION (Restricted Unpickler)
class SafeUnpickler(pickle.Unpickler):
    """
    Only allow unpickling of the UserProfile class.
    Prevents loading arbitrary classes like os.system.
    """
    def find_class(self, module, name):
        if module == "__main__" and name == "UserProfile":
            return super().find_class(module, name)
        # Block everything else
        raise pickle.UnpicklingError(f"Global '{module}.{name}' is forbidden")

# PREVENTION (HMAC Integrity)
def sign_data(data_bytes):
    """Appends a valid HMAC signature to the data."""
    signature = hmac.new(SECRET_KEY, data_bytes, hashlib.sha256).hexdigest()
    # Return format: "base64_data.signature"
    return f"{data_bytes.decode('utf-8')}.{signature}"

def verify_and_split(cookie_value):
    """
    Verifies the HMAC signature. 
    Returns the raw data bytes if valid, None otherwise.
    """
    if not cookie_value or '.' not in cookie_value:
        return None
    
    try:
        data_b64, received_sig = cookie_value.rsplit('.', 1)
        
        # Re-compute signature to verify
        expected_sig = hmac.new(SECRET_KEY, data_b64.encode('utf-8'), hashlib.sha256).hexdigest()
        
        if hmac.compare_digest(expected_sig, received_sig):
            return data_b64.encode('utf-8')
        else:
            print("SECURITY ALERT: Integrity check failed (HMAC mismatch).")
            return None
    except Exception as e:
        print(f"Error verifying signature: {e}")
        return None

# DETECTION (Bytecode Scanning)
def detect_malicious_payload(pickled_data):
    """
    Scans the raw pickle bytes for dangerous module imports
    BEFORE attempting to unpickle.
    """
    dangerous_signatures = [b'os', b'subprocess', b'sys', b'shutil', b'socket', b'ctypes']
    
    for sig in dangerous_signatures:
        if sig in pickled_data:
            print(f"SECURITY ALERT: Malicious module '{sig.decode()}' detected in payload!")
            return True # Malicious
    return False # Clean


# ROUTES

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == 'user' and password == 'password':
            # Create user object
            user_obj = UserProfile(name=username, is_admin=False)
            
            # Serialize
            pickled_obj = pickle.dumps(user_obj)
            encoded_bytes = base64.b64encode(pickled_obj)
            
            # PREVENTION: Sign the cookie
            signed_cookie_value = sign_data(encoded_bytes)
            
            resp = make_response(redirect(url_for('home')))
            resp.set_cookie('user_profile', signed_cookie_value)
            return resp

        return "Invalid login", 401
    
    return render_template('login.html')

@app.route('/')
def home():
    signed_cookie = request.cookies.get('user_profile')
    
    if signed_cookie:
        try:
            # 1. PREVENTION: Verify HMAC
            valid_b64_data = verify_and_split(signed_cookie)
            
            if not valid_b64_data:
                # If signature fails, force logout
                return redirect(url_for('login'))
            
            # Decode base64 to get pickle bytes
            pickle_bytes = base64.b64decode(valid_b64_data)

            # 2. DETECTION: Scan for RCE payloads
            if detect_malicious_payload(pickle_bytes):
                # Log the attack and fail safely (or serve honeypot)
                return "Internal Security Error: Malicious Payload Detected", 403

            # 3. PREVENTION: Safe Unpickler
            # Only loads UserProfile, blocks RCE even if detection missed it
            user_obj = SafeUnpickler(io.BytesIO(pickle_bytes)).load()

            # 4. DECEPTION: Honeypot Logic
            # If user claims to be admin, but we know 'user' isn't an admin...
            if user_obj.is_admin and user_obj.name == 'user':
                print(f"DECEPTION ACTIVE: User '{user_obj.name}' attempted privilege escalation.")
                return render_template('fake_admin.html', user=user_obj)

            return render_template('home.html', user=user_obj)

        except pickle.UnpicklingError as e:
            return f"Security Error: Attempted to load forbidden class. {e}", 403
        except Exception as e:
            return f"An error occurred: {e}", 500
            
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=80)

