import streamlit as st
 # Import the Chatbot class from model.py
from model1 import Chatbot 
import sqlite3
from datetime import datetime
import pandas as pd  # type: ignore
import os
import re
import random
# import json
# Import Google Cloud Storage library
from google.cloud import storage  
import bcrypt 
from fpdf import FPDF

# Initialize Google Cloud Storage client
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = "C:/Users/hayde/Desktop/CBot/Camel/cloud/graphic-parsec-440317-b4-1fe2f52053ca.json"

def upload_to_google_cloud():
    # Database upload
    conn = sqlite3.connect('user_data.db')  # Replace with your actual database path
    tables = {
        "users": pd.read_sql_query("SELECT * FROM users", conn),
        "admins": pd.read_sql_query("SELECT * FROM admins", conn),
        "user_activity": pd.read_sql_query("SELECT * FROM user_activity", conn),
        "quiz_scores": pd.read_sql_query("SELECT * FROM quiz_scores", conn),
        "user_inputs": pd.read_sql_query("SELECT * FROM user_inputs", conn)
    }
    conn.close()

    # Initialize Google Cloud Storage client
    client = storage.Client()
    bucket_name = "camelai"
    bucket = client.bucket(bucket_name)

    # Save each table to JSON and upload to Google Cloud Storage under 'database_backup/'
    for table_name, data in tables.items():
        json_data = data.to_json(orient='records')
        json_file_path = f"{table_name}.json"
        
        # Write JSON data to a file
        with open(json_file_path, 'w') as f:
            f.write(json_data)

        # Upload to Google Cloud Storage under 'database_backup/'
        blob = bucket.blob(f"database_backup/{json_file_path}")
        blob.upload_from_filename(json_file_path)
        os.remove(json_file_path)  # Remove local JSON file after upload

    # Upload project code files under 'project_code/'
    project_files = ["test2.py", "model1.py"]  # Add all files you want to upload

    for file_name in project_files:
        if os.path.exists(file_name):
            blob = bucket.blob(f"project_code/{file_name}")
            blob.upload_from_filename(file_name)

    st.success("Database and project files uploaded to Google Cloud Storage!")

# Initialize the chatbot
chatbot = Chatbot()

# Create directory for file uploads if it doesn't exist
if not os.path.exists("uploads"):
    os.makedirs("uploads")

# Inject custom CSS to style the app with a modern look
def apply_custom_css():
    st.markdown(
        """
        <style>
        /* General styling */
        body {
            background-color: #f5f7fa;
            font-family: 'Segoe UI', sans-serif;
            color: #333;
        }
        .header {
            background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%);
            color: white;
            padding: 15px;
            border-radius: 10px;
            text-align: center;
            font-size: 28px;
            margin-bottom: 20px;
            box-shadow: 0px 4px 15px rgba(0, 0, 0, 0.2);
        }
        .stButton button {
            background-color: #2575fc;
            color: white;
            border-radius: 8px;
            font-weight: bold;
            padding: 10px 20px;
            border: none;
            box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.2);
            transition: all 0.3s ease-in-out;
            margin-top: 10px;
            cursor: pointer;
        }
        .stButton button:hover {
            background-color: #6a11cb;
            transform: translateY(-2px);
        }
        </style>
        """,
        unsafe_allow_html=True
    )

# Initialize the SQLite database
conn = sqlite3.connect('user_data.db')
c = conn.cursor()

# Create tables for user data and admin data
c.execute('''CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT,
                email TEXT UNIQUE,
                role TEXT DEFAULT 'user'  
            )''')

c.execute('''CREATE TABLE IF NOT EXISTS admins (
                admin_username TEXT PRIMARY KEY,
                admin_password TEXT
            )''')

c.execute('''CREATE TABLE IF NOT EXISTS user_activity (
                username TEXT,
                login_timestamp TEXT,
                logout_timestamp TEXT,
                FOREIGN KEY (username) REFERENCES users (username)
            )''')

c.execute('''CREATE TABLE IF NOT EXISTS quiz_scores (
                username TEXT,
                score INTEGER,
                date TEXT,
                FOREIGN KEY (username) REFERENCES users (username)
            )''')

c.execute('''CREATE TABLE IF NOT EXISTS user_inputs (
                username TEXT,
                input_text TEXT,
                response_text TEXT,
                timestamp TEXT,
                FOREIGN KEY (username) REFERENCES users (username)
            )''')
conn.commit()

# Function to verify login credentials
def verify_login(username, password):
    c.execute("SELECT password FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    if result and check_password(password, result[0]):
        return True
    return False

# Function to make sure email is the correct format
def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None

def hash_email(email):
    return bcrypt.hashpw(email.encode(), bcrypt.gensalt()).decode()

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

# Function to verify admin login credentials
def verify_admin_login(admin_username, admin_password):
    c.execute("SELECT * FROM admins WHERE admin_username = ? AND admin_password = ?", (admin_username, admin_password))
    return c.fetchone() is not None

# Function to create a new user with unique name and email validation
def create_user(username, password, email, role='user'):
    if not is_valid_email(email):
        st.error("Invalid email format.")
        return False

    c.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, email))
    if c.fetchone():
        st.error("Username or email already exists.")
        return False
    
    hashed_email = hash_email(email) 

    hashed_password = hash_password(password)

    try:
        c.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)", (username, hashed_password, hashed_email, role))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    
def update_user(username, new_password, new_role):
    c.execute("UPDATE users SET password = ?, role = ? WHERE username = ?", (new_password, new_role, username))
    conn.commit()


def delete_user(username):
    c.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()

def create_admin(admin_username, admin_password):
    # Hash the password
    hashed_password = hash_password(admin_password)  

    try:
        # Store the hashed password in the database
        c.execute("INSERT INTO admins (admin_username, admin_password) VALUES (?, ?)", (admin_username, hashed_password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def update_admin(admin_username, new_password):
    c.execute("UPDATE admins SET admin_password = ? WHERE admin_username = ?", (new_password, admin_username))
    conn.commit()

def log_user_activity(username, activity):
    cursor = conn.cursor()
    
    if activity == "Logged in":
        cursor.execute(
            "INSERT INTO user_activity (username, login_timestamp) VALUES (?, ?)",
            (username, datetime.now())
        )
    elif activity == "Logged out":
        cursor.execute(
            "UPDATE user_activity SET logout_timestamp = ? WHERE username = ? AND logout_timestamp IS NULL",
            (datetime.now(), username)
        )
    
    conn.commit()

def delete_admin(admin_username):
    c.execute("DELETE FROM admins WHERE admin_username = ?", (admin_username,))
    conn.commit()

def get_user_info():
    """Fetches user activity data from the database."""
    query = """
    SELECT 
        user_inputs.username AS user_username, 
        input_text, 
        response_text, 
        timestamp, 
        score, 
        date
    FROM user_inputs
    LEFT JOIN quiz_scores ON user_inputs.username = quiz_scores.username
    ORDER BY user_username, timestamp;
    """
    return c.execute(query).fetchall()

def generate_pdf(user_data):
    """Generates a PDF report of user activity."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    current_user = None
    for row in user_data:
        username, input_text, response_text, timestamp, score, date = row
        if username != current_user:
            if current_user:
                pdf.ln(10)  # Add a line break for clarity
            current_user = username
            pdf.cell(200, 10, f"User: {username}", ln=True, align='L')
            pdf.cell(200, 10, "Inputs and Responses:", ln=True)
        
        # Add question and answer with line breaks
        pdf.multi_cell(0, 10, f"Q: {input_text} | A: {response_text} | Time: {timestamp}")
        
        if score is not None:
            pdf.cell(200, 10, f"Score: {score} | Date: {date}", ln=True)

    # Save and provide PDF download
    pdf_file_path = "C:\\Users\\hayde\\Desktop\\CBot\\Camel\\pdf gen\\user_activity_log.pdf"
    pdf.output(pdf_file_path)
    return pdf_file_path 

def display_user_info():
    """Displays the user activity information."""
    st.title("User Report")

    current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.write(f"**Report generated on:** {current_datetime}")

    # Function to get the users data
    user_data = get_user_info()  
    
    if not user_data:
        st.write("No user activity found.")
        return

    current_user = None
    user_activity = {}

    for row in user_data:
        username, input_text, response_text, timestamp, score, date = row
        if username != current_user:
            if current_user:
                # Print out the details for the last user
                display_user_data(user_activity)
            current_user = username
            user_activity = {
                'username': username,
                'inputs': [],
                'responses': [],
                'timestamps': [],
                'scores': [],
                'dates': []
            }
        
        user_activity['inputs'].append(input_text)
        user_activity['responses'].append(response_text)
        user_activity['timestamps'].append(timestamp)
        user_activity['scores'].append(score)
        user_activity['dates'].append(date)
    
    # Display data for the final user
    if user_activity:
        display_user_data(user_activity)

    # Generate PDF
    # Call the function to generate PDF
    pdf_file_path = generate_pdf(user_data) 

    # Button to download the PDF
    with open(pdf_file_path, "rb") as f:
        st.download_button("Download PDF", f, "user_activity_log.pdf")
        st.success("PDF generated successfully!")

def display_user_data(user_activity):
    """Displays activity for a single user."""
    st.subheader(f"User: {user_activity['username']}")
    
    st.markdown("### Inputs and Responses:")
    for input_text, response_text, timestamp in zip(user_activity['inputs'], user_activity['responses'], user_activity['timestamps']):
        st.markdown(f"**Q:** {input_text}  \n**A:** {response_text}  \n**Time:** {timestamp}")
    
    st.markdown("### Quiz Scores:")
    for score, date in zip(user_activity['scores'], user_activity['dates']):
        if score is not None:
            st.markdown(f"**Score:** {score}  \n**Date:** {date}")

# Admin Page to display all data and add users/admins
def admin_page():
    st.sidebar.markdown("## 🛠️ Admin Dashboard")
    admin_action = st.sidebar.selectbox("Select Action", ["User Management", "Admin Management", "Backup App","Database Info", "Report"])

    if admin_action == "User Management":
        st.subheader("User Management")
        
        # Update User Section
        st.markdown("### Update User")
        update_username = st.text_input("Username to Update", key="update_user_username")
        update_password = st.text_input("New Password", type="password", key="update_user_password")
        update_role = st.selectbox("New Role", ["user", "admin"], key="update_user_role")
        
        if st.button("Update User", key="update_user_button"):
            update_user(update_username, update_password, update_role)
            st.success(f"User '{update_username}' updated successfully.")

        # Delete User Section
        st.markdown("### Delete User")
        delete_username = st.text_input("Username to Delete", key="delete_user_username")
        
        if st.button("Delete User", key="delete_user_button"):
            delete_user(delete_username)
            st.success(f"User '{delete_username}' deleted successfully.")

    elif admin_action == "Admin Management":
        st.subheader("Admin Management")
        
        # Create Admin Section
        st.markdown("### Add Admin")
        new_admin_username = st.text_input("New Admin Username", key="add_admin_username")
        new_admin_password = st.text_input("New Admin Password", type="password", key="add_admin_password")
        
        if st.button("Add Admin", key="add_admin_button"):
            if create_admin(new_admin_username, new_admin_password):
                st.success(f"Admin '{new_admin_username}' added successfully.")
            else:
                st.error("Admin username already exists.")

        # Update Admin Section
        st.markdown("### Update Admin")
        update_admin_username = st.text_input("Admin Username to Update", key="update_admin_username")
        update_admin_password = st.text_input("New Admin Password", type="password", key="update_admin_password")
        
        if st.button("Update Admin", key="update_admin_button"):
            update_admin(update_admin_username, update_admin_password)
            st.success(f"Admin '{update_admin_username}' updated successfully.")

        # Delete Admin Section
        st.markdown("### Delete Admin")
        delete_admin_username = st.text_input("Admin Username to Delete", key="delete_admin_username")
        
        if st.button("Delete Admin", key="delete_admin_button"):
            delete_admin(delete_admin_username)
            st.success(f"Admin '{delete_admin_username}' deleted successfully.")

    elif admin_action == "Backup App":
        st.subheader("App Backup")
        if st.button("Backup App to Cloud", key="backup_app_button"):
            upload_to_google_cloud()

    # Session State Initialization
    if "admin_logged_in" not in st.session_state:
        st.session_state.admin_logged_in = False
    if "page" not in st.session_state:
        st.session_state.page = "login"

    # Display user data
    elif admin_action == "Database Info":
        st.markdown("### Database Info")
        st.subheader("👤 User Data")
        user_data = pd.read_sql_query("SELECT * FROM users", conn)
        st.write(user_data)

        # Display user activity
        st.subheader("📊 User Activity")
        activity_data = pd.read_sql_query("SELECT * FROM user_activity", conn)
        st.write(activity_data)

        # Display quiz scores
        st.subheader("🏆 Quiz Scores")
        quiz_scores = pd.read_sql_query("SELECT * FROM quiz_scores", conn)
        st.write(quiz_scores)

         # Display quiz scores
        st.subheader("🏆 Responses")
        user_inputs = pd.read_sql_query("SELECT * FROM user_inputs", conn)
        st.write(user_inputs)

    elif admin_action == "Report":
        st.subheader("Report")
        display_user_info()


    if st.sidebar.button("Log Out"):
        # Set session states for logout and redirect to login page
        st.session_state.admin_logged_in = False
        st.session_state.page = "login"
        st.success("You have been logged out.")

def get_chat_history(username):
    c.execute(
        "SELECT input_text, response_text, timestamp FROM user_inputs WHERE username = ? ORDER BY timestamp",
        (username,)
    )
    history = c.fetchall()
    return history

def display_chat_history():
    username = st.session_state.get('logged_in_username')
    
    if username:
        st.subheader(f"Chat History for {username}")
        history = get_chat_history(username)
        
        # Display the chat history
        if history:
            for record in history:
                input_text, response_text, timestamp = record
                st.write(f"**User:** {input_text}")
                st.write(f"**AI:** {response_text}")
                st.write(f"*Timestamp:* {timestamp}")
                st.write("---")  # Separator for clarity
        else:
            st.write("No chat history found.")
        
# Main Chatbot Interaction
def chatbot_interaction():
    st.subheader("🤖 Chatbot Assistant")
    user_input = st.text_input("Ask a question:", "")
    
    if user_input:
        response = chatbot.chat(user_input)
        st.write("Bot:", response)

        # Save the interaction to the database
        username = st.session_state.get('logged_in_username')  # Ensure username is stored in session state
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Insert the user input and response into the user_inputs table
        c.execute(
            "INSERT INTO user_inputs (username, input_text, response_text, timestamp) VALUES (?, ?, ?, ?)",
            (username, user_input, response, timestamp)  # Store user_input and response separately
        )
        conn.commit()

# PDF Upload for Knowledge Extraction
def pdf_upload():
    pdf_file = st.file_uploader("Upload a PDF file", type="pdf")
    
    if pdf_file is not None:
        # Generate a unique name for the file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_path = os.path.join("uploads", f"{timestamp}_{pdf_file.name}")

        # Save the uploaded file
        with open(pdf_path, "wb") as f:
            f.write(pdf_file.getbuffer())
            
        # Store the file path in session state for later use
        st.session_state["pdf_path"] = pdf_path
        st.success("PDF saved successfully.")

        # Extract text from the PDF using the chatbot
        extraction_message = chatbot.extract_text_from_pdf(pdf_file)
        st.write(extraction_message)

        # Store extracted sentences in session state if available
        if chatbot.extracted_sentences:
            st.session_state["extracted_sentences"] = chatbot.extracted_sentences
            st.success("PDF content extracted successfully.")
        else:
            st.write("No content available to generate questions.")

# Generate Quiz Functionality
def generate_quiz():
    st.subheader("📝 Quiz Time!")

    # Initialize quiz question index and score if not already in session state
    if "question_index" not in st.session_state:
        st.session_state.question_index = 0
    if "total_score" not in st.session_state:
        st.session_state.total_score = 0

    # Extracted sentences are assumed to be in session state
    sentences = st.session_state.get("extracted_sentences", [])

    # Shuffle the sentences for randomness
    if sentences:
        if "shuffled_sentences" not in st.session_state:
            st.session_state.shuffled_sentences = random.sample(sentences, len(sentences))

        # Loop to find the next suitable sentence
        while st.session_state.question_index < len(st.session_state.shuffled_sentences):
            # Get the current sentence for the quiz question
            current_index = st.session_state.question_index
            sentence = st.session_state.shuffled_sentences[current_index]

            # Ensure the sentence does not contain URLs or existing questions
            if "http" not in sentence and "?" not in sentence:
                # Define keywords for question creation
                keywords = ["Data Science", "Machine Learning", "Data Visualization", "Statistics", "Patterns", "Predictions", 
                            "Artificial intelligence", "AI", "Deep learning", "Neural Network", "Natural Language Processing", "NLP",
                            "Cybersecurity", "Security", "Encryption"]

                # Attempt to replace a keyword with a blank to create the question
                question_sentence = None
                answer = None
                for keyword in keywords:
                    if keyword.lower() in sentence.lower():
                        question_sentence = sentence.replace(keyword, "_____")
                        answer = keyword
                        break

                # If a keyword was found, present the question
                if question_sentence:
                    st.write(question_sentence)

                    # Capture user input
                    user_answer = st.text_input("Your answer:", key=f"user_answer_{current_index}")

                    # Submit and Next buttons
                    submitted = st.button("Submit Answer", key=f"submit_{current_index}")
                    next_question = st.button("Next Question", key=f"next_{current_index}")

                    # Check if "Submit Answer" button was pressed
                    if submitted:
                        correct_answer = answer.lower()
                        is_correct = correct_answer in user_answer.lower()
                        feedback = "Correct!" if is_correct else f"Incorrect. The correct answer is: {answer}"
                        st.write(feedback)

                        # Update the total score if the answer was correct
                        if is_correct:
                            st.session_state.total_score += 1

                    # Move to the next question when "Next Question" is clicked
                    if next_question:
                        st.session_state.question_index += 1
                    return  # Exit the function to avoid processing further sentences this round

            # If no question was created, skip this sentence and move to the next
            st.session_state.question_index += 1

        # If we exit the loop, the quiz is complete
        st.write("Quiz Completed!")
        st.write(f"Your final score is: {st.session_state.total_score} out of {len(sentences)}")

        # Store the score in the database
        username = st.session_state.get('logged_in_username')
        if username:
            c.execute("INSERT INTO quiz_scores (username, score, date) VALUES (?, ?, ?)", 
                      (username, st.session_state.total_score, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
            st.success("Your score has been recorded!")

        # Reset index and score for a new quiz
        st.session_state.question_index = 0
        st.session_state.total_score = 0
    else:
        st.write("No content available to generate questions. Please upload a PDF first.")

# Admin Login Page
def admin_login_page():
    st.markdown("<div class='header'>🔐 Admin Login</div>", unsafe_allow_html=True)
    admin_username = st.text_input("Admin Username", key='admin_login_username')
    admin_password = st.text_input("Admin Password", type="password", key='admin_login_password')
    
    if st.button("Login", key='admin_login_button'):
        if verify_admin_login(admin_username, admin_password):
            st.session_state.admin_logged_in = True
            st.session_state.page = "admin_page"  # Redirect to admin dashboard
            st.success("Admin login successful!")
        else:
            st.error("Invalid admin credentials")

# Login and Sign-Up Pages
def login_page():
    st.markdown("<div class='header'>🔐 Login</div>", unsafe_allow_html=True)
    username = st.text_input("Username", key='login_username')
    password = st.text_input("Password", type="password", key='login_password')
    
    col1, col2, col3 = st.columns([1, 1, 1])  # Adding a third column for the Admin Login button

    with col1:
        if st.button("Login", key='login_button'):
            if verify_login(username, password):
                log_user_activity(username, "Logged in")
                st.session_state.logged_in = True
                st.session_state.logged_in_username = username  # Store username in session state
                st.success("Login successful!")
        else:
            st.error("Invalid username or password")

    with col2:
        if st.button("Sign Up", key='signup_button'):
            st.session_state.page = "signup"
    
    with col3:
        if st.button("Admin Login", key='admin_login_button'):
            st.session_state.page = "admin_login"

def signup_page():
    st.markdown("<div class='header'>📝 Sign Up</div>", unsafe_allow_html=True)
    username = st.text_input("Choose a Username(Not real name)", key='signup_username')
    password = st.text_input("Choose a Password", type="password", key='signup_password')
    email = st.text_input("Enter your Email", key='signup_email')

    col1, col2 = st.columns([1, 1])

    with col1:
        if st.button("Sign Up", key='create_account_button'):
            if create_user(username, password, email):
                st.success("Sign up successful! You can now log in.")
                st.session_state.page = "login"
            else:
                st.error("Sign-up failed. Please check the entered details.")

    with col2:
       if st.button("Login", key='login_button'):
           st.session_state.page = "login"

# Function to handle user logout
def handle_logout(): 
    log_user_activity(st.session_state.logged_in_username, "Logged out")
    st.session_state.logged_in = False
    st.session_state.logged_in_username = None  # Clear the username
    st.success("Logout successful!")

# Main App Layout with Authentication
def main_app():
    st.markdown("<div class='header'>🎓 AI-Powered IT Education Platform</div>", unsafe_allow_html=True)

    st.sidebar.title("📚 Navigation")
    app_mode = st.sidebar.selectbox(
        "Choose the app mode",
        ["Chatbot", "Upload PDF", "Generate Quiz", "Chat History"],
        index=0
    )

    if app_mode == "Chatbot":
        chatbot_interaction()
    elif app_mode == "Upload PDF":
        pdf_upload()
    elif app_mode == "Generate Quiz":
        generate_quiz()  # Call the new generate quiz function
    elif app_mode == "Chat History":
         display_chat_history()  # Display the chat history for the logged-in user


    if st.sidebar.button("Log Out"):
        handle_logout()

# Session state initialization
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "admin_logged_in" not in st.session_state:
    st.session_state.admin_logged_in = False

if "page" not in st.session_state:
    st.session_state.page = "login"

# Apply custom CSS styling
apply_custom_css()

# App Navigation based on authentication
if st.session_state.page == "admin_login":
    admin_login_page()
elif st.session_state.page == "admin_page" and st.session_state.admin_logged_in:
    admin_page()
elif st.session_state.logged_in:
    main_app()
else:
    if st.session_state.page == "login":
        login_page()
    elif st.session_state.page == "signup":
        signup_page()
