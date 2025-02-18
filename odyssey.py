import streamlit as st
import sqlite3
import bcrypt
import os

# Database setup
conn = sqlite3.connect('users.db', check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                  (id INTEGER PRIMARY KEY, username TEXT, email TEXT, password TEXT)''')
conn.commit()

# Hashing functions
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

# Registration function
def register_user(username, email, password):
    hashed = hash_password(password)
    cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                   (username, email, hashed))
    conn.commit()

# Login function
def login_user(email, password):
    cursor.execute('SELECT password FROM users WHERE email = ?', (email,))
    result = cursor.fetchone()
    if result and verify_password(password, result[0]):
        return True
    return False

# Validate email domain
def validate_email(email):
    return email.endswith("@ks.ac.kr")

# File upload directory
UPLOAD_DIR = "uploaded_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Streamlit UI
st.set_page_config(page_title="Odyssey Login", layout="wide")

# Custom styling
st.markdown("""
    <style>
        body { font-family: 'Roboto', sans-serif; background-color: #f3f4f6; }
        .main-header { background-color: #1e3a8a; padding: 20px; color: white; text-align: center; }
        .container { max-width: 600px; margin: auto; padding: 20px; background-color: white; border-radius: 10px; box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.1); }
        .button { background-color: #1e3a8a; color: white; padding: 10px 15px; border: none; border-radius: 5px; }
        .button:hover { background-color: #2563eb; }
    </style>
""", unsafe_allow_html=True)

# Check if user is logged in
if "user" not in st.session_state:
    st.markdown('<div class="main-header"><h1>Odyssey Study App</h1></div>', unsafe_allow_html=True)
    st.subheader("Welcome to Odyssey! Please Log In or Register to Continue.")
    menu = ["Login", "Register"]
    choice = st.selectbox("Menu", menu)

    with st.container():
        if choice == "Login":
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            if st.button("Login", key="login_button", help="Click to log in"):
                if validate_email(email) and login_user(email, password):
                    st.session_state["user"] = email.split('@')[0]
                    st.rerun()
                else:
                    st.error("Invalid email or password, or domain is not allowed.")
        
        elif choice == "Register":
            username = st.text_input("Username")
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            if st.button("Register", key="register_button", help="Click to register"):
                if validate_email(email) and password == confirm_password:
                    register_user(username, email, password)
                    st.success("Account created successfully! Please log in.")
                else:
                    st.error("Invalid email or passwords do not match.")
else:
    # Display main app features after login
    st.markdown('<div class="main-header"><h1>Odyssey Study App</h1></div>', unsafe_allow_html=True)
    st.subheader(f"Welcome, {st.session_state['user']}!")
    
    st.markdown("""
        <h2>Which Feature Do You Want To Use Today? </h2>
        - Flashcards: <a href="https://jmichikoleo.github.io/flashcard/" target="_blank">Try it now</a><br>
        - Notes: <a href="https://jmichikoleo.github.io/notes/" target="_blank">Try it now</a><br>
        - Files Storage: <a href="https://uploadingfile.streamlit.app/" target="_blank">Try it now</a><br>
        - Mindmap: <a href="https://jmichikoleo.github.io/mindmap/" target="_blank">Coming Soon</a><br>
        - Study with GPT: <a href="https://jmichikoleo.github.io/gpt/" target="_blank">Coming Soon</a>
    """, unsafe_allow_html=True)
    


# Close DB connection on exit
import atexit
atexit.register(conn.close)
