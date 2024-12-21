from flask import Flask, request, jsonify, render_template
import sqlite3

app = Flask(__name__)

# Function to check item availability
def check_menu_item_availability(item_name):
    conn = sqlite3.connect('enhanced_menu_management.db')
    cursor = conn.cursor()
    cursor.execute("SELECT Name FROM MenuItems WHERE Name LIKE ?", (f"%{item_name}%",))
    result = cursor.fetchone()
    conn.close()
    return result is not None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search', methods=['POST'])
def search():
    data = request.json
    item_name = data.get('item_name', '').strip()
    if not item_name:
        return jsonify({"status": "error", "message": "Item name cannot be empty"}), 400
    
    is_available = check_menu_item_availability(item_name)
    if is_available:
        return jsonify({"status": "success", "message": f"'{item_name}' is available!"})
    else:
        return jsonify({"status": "success", "message": f"'{item_name}' is not available."})

if __name__ == '__main__':
    app.run(debug=True)
