from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import sqlite3
import json
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Necessary for flash messages

LOG_FILE = "firewall_agent.log"
POLICY_FILE = "policies.json"

# Ensure policy file exists
if not os.path.exists(POLICY_FILE):
    with open(POLICY_FILE, "w") as f:
        # Default structure includes blacklist/whitelist plus an empty "policies" array
        json.dump({
            "whitelist": {"applications": [], "domains": [], "ips": []},
            "blacklist": {"applications": [], "domains": [], "ips": []},
            "policies": []
        }, f, indent=2)

# In-memory placeholders for logs & alerts (not persisted)
alerts = []
logs = []

# Pre-load logs if the log file exists
if os.path.exists(LOG_FILE):
    with open(LOG_FILE, "r") as f:
        logs = f.readlines()

# ---------------------- Utility Functions ----------------------

def create_database():
    """
    Creates the SQLite database and 'users' table if they do not exist.
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def load_policies_from_file():
    """
    Reads and returns the entire contents of 'policies.json' as a Python dictionary.
    Ensures the 'policies' key exists.
    """
    with open(POLICY_FILE, 'r') as f:
        data = json.load(f)
    # If 'policies' is missing for some reason, create an empty list
    if "policies" not in data:
        data["policies"] = []
    return data

def write_policies_to_file(data):
    """
    Writes the updated policy data back to 'policies.json'.
    """
    with open(POLICY_FILE, 'w') as f:
        json.dump(data, f, indent=2)

# ---------------------- Auth & User Management ----------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            session['logged_in'] = True
            session['user'] = user[1]  # user[1] is the username column
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password!', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('user', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        repassword = request.form['repassword']

        if password != repassword:
            flash('Passwords do not match!')
            return redirect(url_for('register'))

        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                           (username, email, password))
            conn.commit()
            conn.close()
            flash('Registration successful!')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already exists!')
            return redirect(url_for('register'))
    return render_template('register.html')

# ---------------------- Dashboard & Index ----------------------

@app.route('/')
@app.route('/dashboard')
def dashboard():
    if 'logged_in' in session:
        return render_template('index.html', user=session['user'])
    else:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))

# ---------------------- Policies API ----------------------

@app.route('/api/policies', methods=['GET'])
def get_policies():
    """
    Returns the 'policies' array from 'policies.json'.
    Example JSON structure in 'policies.json':
    {
      "blacklist": {...},
      "whitelist": {...},
      "policies": [
        {
          "id": 1,
          "application": "msedge.exe",
          "domain": "amazon.in",
          "ip_address": "192.168.1.10",
          "protocol": "TCP"
        },
        ...
      ]
    }
    """
    if 'logged_in' not in session:
        return jsonify({'message': 'Unauthorized'}), 403

    data = load_policies_from_file()
    return jsonify(data["policies"])

@app.route('/api/policies', methods=['POST'])
def add_policy():
    """
    Adds a new policy to the 'policies' array in 'policies.json'.
    """
    if 'logged_in' not in session:
        return jsonify({'message': 'Unauthorized'}), 403

    new_policy = request.json  # Should be a dict with keys: application, domain, ip_address, protocol, etc.
    data = load_policies_from_file()

    # Generate a new ID by taking the max existing ID and adding 1
    existing_policies = data["policies"]
    next_id = 1 if not existing_policies else max(p["id"] for p in existing_policies) + 1
    new_policy["id"] = next_id

    data["policies"].append(new_policy)
    write_policies_to_file(data)

    return jsonify({'message': 'Policy added successfully', 'policy': new_policy}), 201

@app.route('/api/policies/<int:policy_id>', methods=['PUT'])
def update_policy(policy_id):
    """
    Updates an existing policy (matched by 'policy_id') in 'policies.json'.
    """
    if 'logged_in' not in session:
        return jsonify({'message': 'Unauthorized'}), 403

    updated_data = request.json
    data = load_policies_from_file()
    found = False

    for policy in data["policies"]:
        if policy["id"] == policy_id:
            # Update only the keys provided
            policy["application"] = updated_data.get("application", policy["application"])
            policy["domain"] = updated_data.get("domain", policy["domain"])
            policy["ip_address"] = updated_data.get("ip_address", policy["ip_address"])
            policy["protocol"] = updated_data.get("protocol", policy.get("protocol", ""))

            write_policies_to_file(data)
            found = True
            return jsonify({'message': 'Policy updated successfully', 'policy': policy})

    if not found:
        return jsonify({'message': 'Policy not found'}), 404

@app.route('/api/policies/<int:policy_id>', methods=['DELETE'])
def delete_policy(policy_id):
    """
    Deletes a policy from 'policies.json' (matched by 'policy_id').
    """
    if 'logged_in' not in session:
        return jsonify({'message': 'Unauthorized'}), 403

    data = load_policies_from_file()
    original_len = len(data["policies"])
    data["policies"] = [p for p in data["policies"] if p["id"] != policy_id]
    new_len = len(data["policies"])

    if new_len < original_len:
        write_policies_to_file(data)
        return jsonify({'message': 'Policy deleted successfully'}), 200
    else:
        return jsonify({'message': 'Policy not found'}), 404

# ---------------------- Logs API ----------------------

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """
    Returns the content of 'firewall_agent.log' as plain text.
    """
    if 'logged_in' not in session:
        return jsonify({'message': 'Unauthorized'}), 403

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            return f.read()  # Return logs as plain text
    return "", 200

# ---------------------- Alerts API ----------------------

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """
    Returns all alerts in memory as JSON.
    """
    if 'logged_in' not in session:
        return jsonify({'message': 'Unauthorized'}), 403
    return jsonify(alerts)

@app.route('/api/alerts', methods=['POST'])
def add_alert():
    """
    Adds a new alert to the in-memory 'alerts' list (not persisted).
    """
    if 'logged_in' not in session:
        return jsonify({'message': 'Unauthorized'}), 403

    new_alert = request.json.get('alert')
    alerts.append(new_alert)
    return jsonify({'message': 'Alert added successfully', 'alert': new_alert}), 201

# ---------------------- App Entry Point ----------------------

if __name__ == '__main__':
    create_database()
    app.run(debug=True)
