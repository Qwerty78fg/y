import asyncio
import requests
from flask import Flask, redirect, request, jsonify, render_template, session
import discord
from threading import Thread
from functools import wraps


app = Flask(__name__)
app.secret_key = 'your_secret_key'


authorized_users = {}
user_id_global = None
user_ids_global = []


with open("token.txt", "r") as f:
    token = f.read().strip()

CLIENT_ID = "1305178785259196458"
CLIENT_SECRET = "FLQLcsMxlAYdoao2E8IUwjGBHYwLIXVp"
REDIRECT_URI = "http://localhost:5000/callback"


intents = discord.Intents.default()
intents.members = True
bot = discord.Client(intents=intents)

# Global variables
data_ready_event = asyncio.Event()
members_data = []
roles_data = []
user_access_tokens = {}

OAUTH2_URL = (
    f"https://discord.com/api/oauth2/authorize"
    f"?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code"
    f"&scope=identify%20guilds.join"
)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(f'[DEBUG] Checking login status: {session.get("logged_in")}')
        if not session.get('logged_in'):
            return redirect('/')
        return f(*args, **kwargs)
    return decorated_function

@bot.event
async def on_ready():
    print(f'[DEBUG] Bot is logged in as {bot.user}')
    global members_data, roles_data
    if bot.guilds:
        all_members = []
        for guild in bot.guilds:
            guild_members = [{"name": member.name, "id": member.id} for member in guild.members]
            all_members.extend(guild_members)
        seen_ids = set()
        members_data = [member for member in all_members 
                       if member['id'] not in seen_ids and not seen_ids.add(member['id'])]
        roles_data = [{"name": role.name, "id": role.id} for role in bot.guilds[0].roles]
    print(f'[DEBUG] Members data fetched: {len(members_data)} members')
    print(f'[DEBUG] Roles data fetched: {len(roles_data)} roles')
    data_ready_event.set()
    print('[DEBUG] data_ready_event set')

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/invite')
def invite():
    print('[DEBUG] /invite route accessed')
    return redirect(OAUTH2_URL)

@app.route('/callback')
def callback():
    global user_ids_global  #global list
    code = request.args.get("code")
    print(f'[DEBUG] Callback route accessed with code: {code}')
    if not code:
        return jsonify({"error": "No code provided"}), 400

    # code for an access token
    token_data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }
    token_response = requests.post("https://discord.com/api/oauth2/token", data=token_data)
    if token_response.status_code != 200:
        return jsonify({"error": "Failed to exchange code for token"}), 400

    user_data = requests.get(
        "https://discord.com/api/users/@me",
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"}
    ).json()

    
    user_id = user_data.get("id")
    user_ids_global.append(user_id) 
    print(f"[DEBUG] Access token stored for user {user_id}: {token_response.json()['access_token']}")


    user_response = requests.get(
        "https://discord.com/api/users/@me",
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"}
    )
    print(f'[DEBUG] User info response status: {user_response.status_code}')
    
    if not user_response.ok:
        return jsonify({"error": "Failed to get user data"}), 500
        
    user_data = user_response.json()
    user_id = user_data.get("id")
    print(f'[DEBUG] Retrieved user ID: {user_id}')

    # store
    user_access_tokens[user_id] = token_response.json()['access_token']
    authorized_users[user_id[:-2]] = token_response.json()['access_token']  
    print(f"[DEBUG] Access token stored for user {user_id}: {token_response.json()['access_token']}")

    
    if not bot.guilds:
        return jsonify({"error": "Bot is not in any guild"}), 400

    guild_id = bot.guilds[0].id

    #Add
    add_user_response = requests.put(
        f"https://discord.com/api/guilds/{guild_id}/members/{user_id}",
        headers={"Authorization": f"Bot {token}"},
        json={"access_token": token_response.json()['access_token']}
    )

    print(f'[DEBUG] Add user to guild response status: {add_user_response.status_code}')
    print(f'[DEBUG] Add user to guild response content: {add_user_response.text}')

    if add_user_response.status_code == 201:
        return jsonify({"success": "User added to guild"}), 201
    else:
        return jsonify({"error": f"Failed to add user to guild: {add_user_response.status_code}"}), add_user_response.status_code

@app.route('/members')
@login_required
def get_members():
    print('[DEBUG] /members route accessed')
    asyncio.run(data_ready_event.wait())
    return jsonify(members_data)

@app.route('/roles')
@login_required
def get_roles():
    print('[DEBUG] /roles route accessed')
    asyncio.run(data_ready_event.wait())
    return jsonify(roles_data)

@app.route('/servers')
@login_required
def get_servers():
    servers = [{"id": guild.id, "name": guild.name} for guild in bot.guilds]
    return jsonify(servers)

@app.route('/add_user_to_second_server', methods=['POST'])
@login_required
def add_user_to_second_server():
    global user_ids_global
    data = request.json
    user_index = data.get('user_index') 
    server_index = data.get('server_index')

    
    try:
        user_index = int(user_index)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid user index"}), 400

    print(f'[DEBUG] Attempting to add user {user_ids_global[user_index]} to server index {server_index}')
    
    if user_index is None or server_index is None or user_index >= len(user_ids_global):
        return jsonify({"error": "Missing user_index or server_index"}), 400

    user_id = user_ids_global[user_index]


    if user_id not in user_access_tokens:
        return jsonify({"error": "User hasn't authenticated yet"}), 401

    user_in_guild_0 = None
    for member in bot.guilds[0].members:
        if str(member.id) == user_id:
            user_in_guild_0 = member
            break
    
    if not user_in_guild_0:
        return jsonify({"error": "User not found in the first guild"}), 404

    headers = {"Authorization": f"Bot {token}"}
    add_user_response = requests.put(
        f"https://discord.com/api/guilds/{bot.guilds[1].id}/members/{user_in_guild_0.id}",
        headers=headers,
        json={"access_token": user_access_tokens[user_id]}  #stored access token
    )

    if add_user_response.status_code == 201:
        return jsonify({"success": True}), 201
    else:
        print(f'[DEBUG] Failed to add user: {add_user_response.status_code}, Response: {add_user_response.text}')
        return jsonify({"error": f"Failed to add user: {add_user_response.status_code}"}), add_user_response.status_code

@app.route('/get_user_ids', methods=['GET'])
def get_user_ids():
    global user_ids_global  #global list
    return jsonify(user_ids_global)

def run_flask():
    print('[DEBUG] Flask app is starting...')
    app.run(debug=True, use_reloader=False)

@bot.event
async def on_member_join(member):
    print(f'[DEBUG] New member joined: {member.name}')
    global members_data
    
    members_data = [{"name": member.name, "id": member.id} for member in bot.guilds[0].members]
    print(f'[DEBUG] Members data updated: {len(members_data)} members')

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    password = data.get('password')

    
    if password == "1234":
        session['logged_in'] = True  #session variable
        print('[DEBUG] User logged in successfully.')
        return jsonify({"success": True}), 200
    else:
        return jsonify({"success": False, "error": "Incorrect password"}), 401

@app.route('/admin')
def admin_panel():
    if not session.get('logged_in'):
        return redirect('/')
    return render_template('index.html')  #admin panel template

if __name__ == "__main__":
    print('[DEBUG] Starting Flask in a separate thread...')
    flask_thread = Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()

    print('[DEBUG] Starting bot...')
    bot.run(token)
