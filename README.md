<h1 align='center'> Password Manager 🔐 </h1>  
 
This is a basic **password manager** application built with Python and SQLite. It allows users to securely store, retrieve, and manage their passwords for different accounts in a centralized and encrypted database.

---

### 🌟 **Features**  
- Securely stores credentials in a local SQLite database 🛡️.  
- Add, view, update, or delete account passwords easily.  
- Simple and intuitive command-line interface (CLI).  
- Encrypted storage for sensitive information 🔒.

---

### 🗂️ **Project Structure**  
```plaintext
password_manager/
├── database/               # Contains the SQLite database and related 
│   ├── database.py         # Handles database operations
│   └── passwords.db        # Local SQLite database file
│
├── resources/               # Contains images and icons to prettify the application
│   ├── icons/               # Contains the icons
         └── ...             # icons
│   └── ...                  # images
│
├── tests/                  # Contains the unit tests 
│   ├── test_database.py    # Tests the database related functions
│   ├── test_security.py    # Tests the security related functions
│   └── test_utils.py       # Tests the auxiliary functions
│
├── ui/                     # Contains the UI  
│   └── main_window.py      # UI code
│ 
├── main_gui.py             # Entry point for the application with UI
├── main.py                 # Entry point for the application
├── master_password.txt     # Contains the hashed master password
├── README.md
├── requirements.txt        # Dependencies for the project
├── security.py             # Contains security-related scripts
└── utils.py                # utility functions / generic tools
```

---

### ⚡ **Quick Start**  

1. **Clone the Repository**  
   ```bash
   git clone https://github.com/Ad882/password-manager
   cd ./password-manager
   ```

2. **Install Dependencies**  
   Ensure you have Python 3.8+ installed. Install required libraries:  
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Application**  
   Launch the main script to start the password manager:  
   ```bash
   python main.py
   ```

---

### 🛠️ **How It Works**  

- **Database Initialization**:  
  At the first launch, the application automatically creates the SQLite database `passwords.db` with a table to store account details.  

- **Add New Account**:  
  Enter a service name, username, and password to save it securely in the database.  

- **Retrieve Credentials**:  
  Search for stored credentials by service name.  

- **Update or Delete**:  
  Modify existing credentials or delete unused entries.

---

### 🔗 **Dependencies**  

- `Python 3.8+` 🐍  
- `SQLite` 🗄️  
- `bcrypt` 🔒  
- `unittest` 🧪
- `pillow` 💤

---

### 🌐 **Language**  
This application operates **entirely in French**!


---

### 🧪 **Running Tests**

To ensure the integrity and functionality of the password manager, unit tests have been included for key components like encryption, database operations, and utility functions. To run the tests, use the following command to run all the unit tests in the `tests/` folder:
  ```bash
  python -m unittest discover tests
  ```
