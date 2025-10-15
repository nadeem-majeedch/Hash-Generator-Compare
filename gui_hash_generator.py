import hashlib
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

def generate_file_hash(filename, algorithm, chunk_size=4096):
    """Generate hash for a given file using the selected algorithm."""
    if not os.path.exists(filename):
        return None, "❌ File not found!"

    try:
        hasher = hashlib.new(algorithm)
        with open(filename, "rb") as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
        return hasher.hexdigest(), None
    except Exception as e:
        return None, f"⚠️ Error reading file: {e}"

def generate_text_hash(text, algorithm):
    """Generate hash for input text."""
    encoded_text = text.encode()
    hasher = hashlib.new(algorithm)
    hasher.update(encoded_text)
    return hasher.hexdigest()

def select_file(entry_widget):
    """Open file dialog to select file."""
    file_path = filedialog.askopenfilename()
    if file_path:
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, file_path)

def hash_string():
    """Handle string hashing."""
    text = text_input.get("1.0", tk.END).strip()
    algorithm = algorithm_var.get()

    if not text:
        messagebox.showwarning("Warning", "Please enter some text to hash.")
        return

    hash_value = generate_text_hash(text, algorithm)
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, f"🔹 Algorithm: {algorithm.upper()}\n")
    output_text.insert(tk.END, f"🔹 Input Text: {text}\n")
    output_text.insert(tk.END, f"🔹 Hash Code:\n{hash_value}\n")

def hash_file():
    """Handle file hashing."""
    file_path = file_entry.get()
    algorithm = algorithm_var.get()

    if not os.path.exists(file_path):
        messagebox.showerror("Error", "File not found! Please select a valid file.")
        return

    hash_value, error = generate_file_hash(file_path, algorithm)
    output_text.delete("1.0", tk.END)
    if error:
        output_text.insert(tk.END, error)
    else:
        output_text.insert(tk.END, f"🔹 Algorithm: {algorithm.upper()}\n")
        output_text.insert(tk.END, f"🔹 File: {file_path}\n")
        output_text.insert(tk.END, f"🔹 Hash Code:\n{hash_value}\n")

def compare_files():
    """Handle file comparison."""
    file1 = file_entry1.get()
    file2 = file_entry2.get()
    algorithm = algorithm_var.get()

    if not os.path.exists(file1) or not os.path.exists(file2):
        messagebox.showerror("Error", "Please select valid file paths.")
        return

    hash1, err1 = generate_file_hash(file1, algorithm)
    hash2, err2 = generate_file_hash(file2, algorithm)

    output_text.delete("1.0", tk.END)

    if err1:
        output_text.insert(tk.END, err1)
        return
    if err2:
        output_text.insert(tk.END, err2)
        return

    output_text.insert(tk.END, f"🔹 Hash of {os.path.basename(file1)}:\n{hash1}\n\n")
    output_text.insert(tk.END, f"🔹 Hash of {os.path.basename(file2)}:\n{hash2}\n\n")

    if hash1 == hash2:
        output_text.insert(tk.END, "✅ The files are identical (hashes match).")
    else:
        output_text.insert(tk.END, "❌ The files are different (hashes do not match).")

# Create main window
root = tk.Tk()
root.title("🔒 Hash Generator & File Comparator")
root.geometry("700x600")
root.resizable(False, False)

# Notebook Tabs
notebook = ttk.Notebook(root)
notebook.pack(pady=10, expand=True)

# ===== Tab 1: String Hashing =====
tab1 = ttk.Frame(notebook)
notebook.add(tab1, text="Hash Text")

tk.Label(tab1, text="Enter text to hash:", font=("Arial", 12)).pack(pady=5)
text_input = tk.Text(tab1, height=5, width=70)
text_input.pack(pady=5)

tk.Button(tab1, text="Generate Hash", command=hash_string, bg="#4CAF50", fg="white", width=20).pack(pady=10)

# ===== Tab 2: File Hashing =====
tab2 = ttk.Frame(notebook)
notebook.add(tab2, text="Hash File")

tk.Label(tab2, text="Select a file to hash:", font=("Arial", 12)).pack(pady=5)
file_entry = tk.Entry(tab2, width=60)
file_entry.pack(pady=5, side=tk.LEFT, padx=(10, 0))
tk.Button(tab2, text="Browse", command=lambda: select_file(file_entry)).pack(pady=5, side=tk.LEFT)
tk.Button(tab2, text="Generate File Hash", command=hash_file, bg="#4CAF50", fg="white", width=20).pack(pady=10)

# ===== Tab 3: File Comparison =====
tab3 = ttk.Frame(notebook)
notebook.add(tab3, text="Compare Files")

tk.Label(tab3, text="Select first file:", font=("Arial", 12)).pack(pady=5)
file_entry1 = tk.Entry(tab3, width=60)
file_entry1.pack(pady=5, side=tk.LEFT, padx=(10, 0))
tk.Button(tab3, text="Browse", command=lambda: select_file(file_entry1)).pack(pady=5, side=tk.LEFT)

tk.Label(tab3, text="Select second file:", font=("Arial", 12)).pack(pady=10)
file_entry2 = tk.Entry(tab3, width=60)
file_entry2.pack(pady=5, side=tk.LEFT, padx=(10, 0))
tk.Button(tab3, text="Browse", command=lambda: select_file(file_entry2)).pack(pady=5, side=tk.LEFT)

tk.Button(tab3, text="Compare Files", command=compare_files, bg="#4CAF50", fg="white", width=20).pack(pady=15)

# ===== Common Section: Hash Algorithm Selection =====
tk.Label(root, text="Select Hash Algorithm:", font=("Arial", 12, "bold")).pack()
algorithm_var = tk.StringVar(value="sha256")
algo_menu = ttk.Combobox(root, textvariable=algorithm_var, values=["md5", "sha1", "sha224", "sha256", "sha384", "sha512"], state="readonly", width=20)
algo_menu.pack(pady=5)

# ===== Output Section =====
tk.Label(root, text="Output:", font=("Arial", 12, "bold")).pack()
output_text = tk.Text(root, height=10, width=80)
output_text.pack(pady=10)

# Run the GUI
root.mainloop()
