<h1 align='center'> Password Manager 🔐 </h1>  
 
This is a basic **password manager** application built with Python and SQLite. It allows users to securely store, retrieve, and manage their passwords for different accounts in a centralized and encrypted database.

<br>

## 🌟 **Features**  
- Encrypted storage for sensitive information. 
- Add, view, update, or delete account passwords easily.  
- Simple and intuitive command-line interface (CLI)  or application.   
  ⚠️ The CLI is in French 🇫🇷

<br>

## 🗂️ **Project structure**  
```plaintext
password_manager/
├── database/               # Contains the SQLite database and related 
│   ├── database.py         # Handles database operations
│   └── passwords.db        # Local SQLite database file
│
├── resources/               # Contains images and icons to prettify the application
│   ├── icons/               # Contains the icons
│   │     └── ...            # icons
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

<br>
<br>

## ⚡ **Quick start**  

1. **Clone the repository**  
   ```bash
   git clone https://github.com/Ad882/password-manager
   cd ./password-manager
   ```

2. **Install dependencies**  
   Ensure you have Python 3.8+ installed. Install required libraries:  
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**  
   Launch the main script to start the password manager:   
   a) To start the command-line application:
     ```bash
     python main.py
     ```
   b) To start the "user friendly" application:
     ```bash
     python main_gui.py
     ```

<br>

## 🔗 **Dependencies**  

- `Python 3.8+` 🐍  
- `SQLite` 🗄️  
- `bcrypt` 🔒  
- `unittest` 🧪
- `pillow` 💤


<br>
<br>

## 🧪 **Running tests**

To ensure the integrity and functionality of the password manager, unit tests have been included for key components like encryption, database operations, and utility functions. To run the tests, use the following command to run all the unit tests in the `tests/` folder:
  ```bash
  python -m unittest discover tests
  ```
