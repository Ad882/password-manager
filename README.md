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
├── .gitignore              # Git ignore file
├── app                     # Executable file generated from main_gui.py
├── LICENSE                 # License file
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


<br>
<br>

## 📱 **Generate the application executable file**
For everyday use, it's more practical to have a desktop application than to have to go into the terminal, move to the right folder and run the python script...

To do this, simply follow the steps below: 
1. **Install `pyinstaller`**  
  ```bash
  pip install pyinstaller
  ```

2. **Create the executable**  
  ```bash
  pyinstaller --onefile --windowed --hidden-import PIL._tkinter_finder main_gui.py
  ```

3. **Move the executable**  
The exe file is now created in a `/dist` folder. It cannot be launched from there, move it the the projetc's root.

1. **Create a shortcut on the desktop (optional)** 
Follow the steps:
  - Open a terminal and create a `.desktop` file in the `~/Desktop/` folder:
  ```bash
  nano ~/Desktop/password_manager.desktop
  ```

  - Add this to the file:
  ```
  [Desktop Entry]
  Version=1.0
  Name=Password Manager
  Comment=Mon gestionnaire de mots de passe
  Exec=/home/user/password-manager/app
  Icon=/home/user/password-manager/resources/lock.png
  Terminal=false
  Type=Application
  Categories=Utility;
  Path=/home/user/password-manager/
  ```

⚠️ **Warning**: Replace the `/home/user/password-manager/` path by the current path, but not by an absolute path!

A new icon should arise on the desktop menu.

  - Run this command to allow the shortcut to run:

  ```bash
  chmod +x ~/Desktop/password_manager.desktop
  ```


- Right click on the application and click on `activate execution`.