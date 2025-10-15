# 🔒 Hash Generator & File Comparator

## 🧭 Overview
The **Hash Generator & File Comparator** is a Python application that allows users to:
- Generate **hash codes** for **text** or **files**
- **Compare two files** to verify their integrity or detect duplicates  
- Use a **graphical interface (Tkinter)** for easy operation  
- Supports multiple hashing algorithms: **MD5**, **SHA1**, **SHA224**, **SHA256**, **SHA384**, **SHA512**

This project is ideal for **students, developers, or cybersecurity learners** who want to understand how hashing works and how to verify file integrity.

---

## ⚙️ Features

✅ **3 Modes of Operation**
1. **Hash Text:** Enter any string and generate its hash instantly.  
2. **Hash File:** Select any file and compute its hash using the algorithm of your choice.  
3. **Compare Files:** Compare two files to check if they are identical (based on their hash values).

✅ **Supported Algorithms**
- MD5  
- SHA1  
- SHA224  
- SHA256  
- SHA384  
- SHA512  

✅ **Other Highlights**
- Clean **Graphical User Interface** built with Tkinter  
- Supports **large files** (reads in chunks)  
- Displays algorithm, input, and hash in an organized format  
- Includes **error handling** for missing or invalid files  
- Optional **console versions** included for quick hashing from terminal

---

## 🏗️ Project Structure

Hash-Generator-Compare/
│
├── gui_hash_generator.py # Main Tkinter GUI application
├── hash_generator.py # Console version (string + file hashing)
├── file_compare.py # Console version for comparing two files
├── README.md # Project documentation (this file)
└── requirements.txt # Required dependencies

yaml
Copy code

---

## 🧩 Installation

### **1️⃣ Clone the Repository**
```bash
git clone https://github.com/<your-username>/Hash-Generator-Compare.git
cd Hash-Generator-Compare
2️⃣ Create a Virtual Environment (Optional but Recommended)
bash
Copy code
python -m venv venv
source venv/bin/activate    # On macOS/Linux
venv\Scripts\activate       # On Windows
3️⃣ Install Dependencies
bash
Copy code
pip install -r requirements.txt
(You can also install manually if needed — this project mainly uses tkinter and Python’s built-in hashlib module.)

🚀 Usage
🖥️ GUI Version
Run the graphical interface:

bash
Copy code
python gui_hash_generator.py
Features in GUI:

Tab 1: Hash any text input

Tab 2: Select and hash a file

Tab 3: Compare two files

Choose your hash algorithm from a dropdown menu.

Copy or review hash results in the output area.

💻 Console Version
Hash a string or file directly from terminal:

🔹 Hash a String
bash
Copy code
python hash_generator.py
Example Interaction:

vbnet
Copy code
Enter a string to hash: hello
Select algorithm: SHA256
Hash Code: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
🔹 Compare Two Files
bash
Copy code
python file_compare.py
Example Output:

sql
Copy code
Hash of file1.txt: 5eb63bbbe01eeed093cb22bb8f5acdc3
Hash of file2.txt: 5eb63bbbe01eeed093cb22bb8f5acdc3
✅ The files are identical (hashes match)
🧠 How It Works
🔹 Hashing Logic
Uses Python’s built-in hashlib library.

Converts text or file content to bytes.

Applies the selected hash algorithm to generate a unique hexadecimal digest.

🔹 File Comparison
Reads both files in chunks for efficiency.

Computes their hashes.

Compares the resulting digests to check for equality.

🧰 Technologies Used
Component	Description
Python 3.x	Core programming language
hashlib	Built-in module for secure hash functions
tkinter	GUI library for Python
os	File handling and system utilities

🧪 Example Screenshots
GUI Window	File Comparison

(Replace placeholders with your actual screenshots once uploaded.)

🧩 Future Enhancements
🚀 Planned features:

Add Save Results button (export hash/comparison output to text file)

Drag-and-drop file support

Dark mode interface

Add checksum verification feature for downloaded files

Option to compare multiple files at once

🧑‍💻 Author
Developed by: Dr. Muhammad Nadeem Majeed
📧 nadeem.majeed@pucit.edu.pk
🌐 GitHub Profile

🪪 License
This project is licensed under the MIT License.
You’re free to use, modify, and distribute this software with proper attribution.

⭐ If you like this project, please star the repository!
Your feedback helps improve open-source tools like this 💙

# Python Standard Library Modules
hashlib
os
tkinter

# Optional for enhanced UI (if using ttk themes)
ttkbootstrap==1.10.1
