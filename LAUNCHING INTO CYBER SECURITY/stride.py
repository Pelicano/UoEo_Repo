import logging
import re
import hashlib
from datetime import datetime

class Threat:
    def __init__(self, threat_type, description):
        self.threat_type = threat_type
        self.description = description

 # Define the model
class StrideModel:
    def __init__(self, system_name):
        self.system_name = system_name
        self.threats = []
        logging.basicConfig(filename='security.log', level=logging.DEBUG,
                            format='%(asctime)s - %(levelname)s - %(message)s')

    def add_threat(self, threat_type, description):
        threat = Threat(threat_type, description)
        self.threats.append(threat)
        logging.warning(f'Threat detected: {threat.threat_type} - {threat.description}')

    def get_threats(self, threat_type=None):
        if threat_type is None:
            return self.threats
        else:
            return [threat for threat in self.threats if threat.threat_type == threat_type]

    def analyze_spoofing(self, user_input):
        pattern = re.compile("[^a-zA-Z0-9]")
        if pattern.search(user_input) is not None:
            self.add_threat("Spoofing", "User input includes non-alphanumeric characters")

    def analyze_tampering(self, request_data):
        if len(request_data) > 0:
            self.add_threat("Tampering", "Request data is not empty")
        
        for key, value in request_data.items():
            if re.search(r'[^\w\s\-.,@]', value):
                self.add_threat("Tampering", "Request data includes non-alphanumeric characters")

    def analyze_repudiation(self, response_data):
        if response_data is not None:
            self.add_threat("Repudiation", "Response data is not None")

    def analyze_information_disclosure(self, response_data):
        if "password" in response_data:
            self.add_threat("Information Disclosure", "Response data includes password")
            
        for key, value in response_data.items():
            if key == "password_hash":
                self.add_threat("Information Disclosure", "Response data includes password hash")

    def analyze_denial_of_service(self, request_data):
        if len(request_data) > 10000:
            self.add_threat("Denial of Service", "Request data is too large")

    def analyze_elevation_of_privilege(self, user_role):
        if user_role == "admin":
            self.add_threat("Elevation of Privilege", "User has admin role")
    
    def authenticate_user(self, username, password):
        # Authenticate user based on username and password
        # Return True if authentication is successful, False otherwise
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        if username == "admin" and hashed_password == "e6a8a2d50c6b9d9eb5e5c0f5a7a62c5a75f063d2a123e0647a1d57c41d7db994":
            logging.info(f"User {username} successfully authenticated")
            return True
        else:
            logging.warning(f"User {username} failed authentication")
            return False

            # Example Usage Section

# Create a new StrideModel for a system named "My System"
model = StrideModel("My System")

# Analyze user input for spoofing
user_input = "Hello, world!"
model.analyze_spoofing(user_input)

# Analyze request data for tampering
request_data = {"username": "alice", "password": "secret123"}
model.analyze_tampering(request_data)

# Authenticate the user
if model.authenticate_user("alice", "secret123"):
    # User is authenticated - perform some action
    print("User is authenticated - performing action...")
else:
    # User is not authenticated - display an error message
    print("Error: User authentication failed.")

# Analyze Repudiation
model.analyze_repudiation(None)
model.analyze_repudiation("Hello, World!")

# Analyze Information Disclosure
model.analyze_information_disclosure({})
model.analyze_information_disclosure({"username": "Alice", "password": "pa$$word"})
model.analyze_information_disclosure({"username": "Bob", "password_hash": "6f047ccaa1ed3e8e05cde1c7ebc7d958"})

# Analyze Denial of Service
model.analyze_denial_of_service({})
model.analyze_denial_of_service({"name": "Alice", "age": 25, "address": "123 Main St." * 2000})

# Analyze Elevation of Privilege
model.analyze_elevation_of_privilege("guest")
model.analyze_elevation_of_privilege("admin")

# Authenticate user
model.authenticate_user("admin", "password")
model.authenticate_user("guest", "password123")

# Get all threats
threats = model.get_threats()
for threat in threats:
    print(f"{threat.threat_type}: {threat.description}")

# Get all Tampering threats
tampering_threats = model.get_threats("Tampering")
for threat in tampering_threats:
    print(f"{threat.threat_type}: {threat.description}")
