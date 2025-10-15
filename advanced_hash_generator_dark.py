# ======================================================
# File: advanced_hash_generator_dark.py
# Author: Your Name
# Project: Hash Generator & File Comparator (Dark Mode)
# Description: Modern GUI version with ttkbootstrap theme
# ======================================================

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
import hashlib
import os
import logging
import pyperclip

# ---------------- Logging ----------------
logging.basicConfig(
    filename="hash_generator.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ---------------- Hash Functions ----------------

def compute_hash_from_text(text, algorithm):
    """Compute hash from text input"""
    try:
        hash_func = getattr(hashlib, algorithm)
        return hash_func(text.encode()).hexdigest()
    except Exception as e:
        logging.error(f"Error hashing text: {e}")
        return "Error computing hash."


def compute_hash_from_file(filepath, algorithm):
    """Compute hash from file content"""
    try:
        hash_func = getattr(hashlib, algorithm)()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except FileNotFoundError:
        messagebox.showerror("Error", f"File not found: {filepath}")
        return ""
    except Exception as e:
        logging.error(f"Error hashing file: {e}")
        return "Error computing file hash."


# ---------------- GUI Application ----------------

class HashGeneratorApp(ttk.Window):
    def __init__(self):
        super().__init__(title="🔒 Advanced Hash Generator & Comparator (Dark Mode)", themename="darkly")
        self.geometry("900x650")
        self.resizable(False, False)

        self.algorithms = sorted(hashlib.algorithms_guaranteed)
        self.create_notebook()

    def create_notebook(self):
        """Create and configure tabbed interface"""
        notebook = ttk.Notebook(self, bootstyle="dark")
        notebook.pack(expand=True, fill=BOTH, padx=10, pady=10)

        tab_text = ttk.Frame(notebook)
        tab_file = ttk.Frame(notebook)
        tab_compare = ttk.Frame(notebook)

        notebook.add(tab_text, text="🔠 Hash Text")
        notebook.add(tab_file, text="📁 Hash File")
        notebook.add(tab_compare, text="⚖️ Compare Files")

        self.create_text_tab(tab_text)
        self.create_file_tab(tab_file)
        self.create_compare_tab(tab_compare)

    # ---------------- TAB 1: Text Hash ----------------
    def create_text_tab(self, tab):
        ttk.Label(tab, text="Enter Text to Hash:", font=("Arial", 12, "bold")).pack(pady=10)
        self.text_input = ttk.Text(tab, height=6, width=100)
        self.text_input.pack(pady=5)

        frame = ttk.Frame(tab)
        frame.pack(pady=5)
        ttk.Label(frame, text="Select Algorithm:").pack(side=LEFT, padx=5)
        self.alg_choice_text = ttk.Combobox(frame, values=self.algorithms, state="readonly", width=20, bootstyle="info")
        self.alg_choice_text.set("sha256")
        self.alg_choice_text.pack(side=LEFT)

        ttk.Button(tab, text="Generate Hash", bootstyle="success-outline", command=self.generate_text_hash).pack(pady=10)
        ttk.Button(tab, text="Copy Hash", bootstyle="secondary-outline", command=self.copy_text_hash).pack(pady=5)

        self.hash_output_text = ttk.Text(tab, height=5, width=100, wrap="word")
        self.hash_output_text.pack(pady=10)

    def generate_text_hash(self):
        text = self.text_input.get("1.0", "end").strip()
        algorithm = self.alg_choice_text.get()
        if not text:
            messagebox.showwarning("Warning", "Please enter text to hash.")
            return
        hash_value = compute_hash_from_text(text, algorithm)
        self.hash_output_text.delete("1.0", "end")
        self.hash_output_text.insert("end", hash_value)

    def copy_text_hash(self):
        result = self.hash_output_text.get("1.0", "end").strip()
        if result:
            pyperclip.copy(result)
            messagebox.showinfo("Copied", "Hash copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No hash to copy.")

    # ---------------- TAB 2: File Hash ----------------
    def create_file_tab(self, tab):
        ttk.Label(tab, text="Select File to Hash:", font=("Arial", 12, "bold")).pack(pady=10)

        frame = ttk.Frame(tab)
        frame.pack(pady=5)
        self.file_path_var = ttk.StringVar()
        ttk.Entry(frame, textvariable=self.file_path_var, width=70).pack(side=LEFT, padx=5)
        ttk.Button(frame, text="Browse", bootstyle="info-outline", command=self.browse_file).pack(side=LEFT)

        frame2 = ttk.Frame(tab)
        frame2.pack(pady=10)
        ttk.Label(frame2, text="Select Algorithm:").pack(side=LEFT, padx=5)
        self.alg_choice_file = ttk.Combobox(frame2, values=self.algorithms, state="readonly", width=20, bootstyle="info")
        self.alg_choice_file.set("sha256")
        self.alg_choice_file.pack(side=LEFT)

        ttk.Button(tab, text="Generate File Hash", bootstyle="success-outline", command=self.generate_file_hash).pack(pady=10)
        ttk.Button(tab, text="Copy Hash", bootstyle="secondary-outline", command=self.copy_file_hash).pack(pady=5)

        self.hash_output_file = ttk.Text(tab, height=5, width=100, wrap="word")
        self.hash_output_file.pack(pady=10)

    def browse_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            self.file_path_var.set(filepath)

    def generate_file_hash(self):
        filepath = self.file_path_var.get()
        algorithm = self.alg_choice_file.get()
        if not os.path.exists(filepath):
            messagebox.showerror("Error", "Please select a valid file.")
            return
        hash_value = compute_hash_from_file(filepath, algorithm)
        self.hash_output_file.delete("1.0", "end")
        self.hash_output_file.insert("end", hash_value)

    def copy_file_hash(self):
        result = self.hash_output_file.get("1.0", "end").strip()
        if result:
            pyperclip.copy(result)
            messagebox.showinfo("Copied", "Hash copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No hash to copy.")

    # ---------------- TAB 3: Compare Files ----------------
    def create_compare_tab(self, tab):
        ttk.Label(tab, text="Compare Two Files:", font=("Arial", 12, "bold")).pack(pady=10)

        frame1 = ttk.Frame(tab)
        frame1.pack(pady=5)
        self.file1_var = ttk.StringVar()
        ttk.Entry(frame1, textvariable=self.file1_var, width=70).pack(side=LEFT, padx=5)
        ttk.Button(frame1, text="Browse File 1", bootstyle="info-outline",
                   command=lambda: self.browse_compare_file(self.file1_var)).pack(side=LEFT)

        frame2 = ttk.Frame(tab)
        frame2.pack(pady=5)
        self.file2_var = ttk.StringVar()
        ttk.Entry(frame2, textvariable=self.file2_var, width=70).pack(side=LEFT, padx=5)
        ttk.Button(frame2, text="Browse File 2", bootstyle="info-outline",
                   command=lambda: self.browse_compare_file(self.file2_var)).pack(side=LEFT)

        frame3 = ttk.Frame(tab)
        frame3.pack(pady=10)
        ttk.Label(frame3, text="Select Algorithm:").pack(side=LEFT, padx=5)
        self.alg_choice_compare = ttk.Combobox(frame3, values=self.algorithms, state="readonly", width=20, bootstyle="info")
        self.alg_choice_compare.set("sha256")
        self.alg_choice_compare.pack(side=LEFT)

        ttk.Button(tab, text="Compare Files", bootstyle="success-outline", command=self.compare_files).pack(pady=15)
        self.result_label = ttk.Label(tab, text="", font=("Arial", 14, "bold"))
        self.result_label.pack(pady=10)

    def browse_compare_file(self, var):
        filepath = filedialog.askopenfilename()
        if filepath:
            var.set(filepath)

    def compare_files(self):
        file1 = self.file1_var.get()
        file2 = self.file2_var.get()
        algorithm = self.alg_choice_compare.get()

        if not os.path.exists(file1) or not os.path.exists(file2):
            messagebox.showerror("Error", "Please select valid files for comparison.")
            return

        hash1 = compute_hash_from_file(file1, algorithm)
        hash2 = compute_hash_from_file(file2, algorithm)

        if hash1 == hash2:
            self.result_label.config(text="✅ Files are IDENTICAL", bootstyle="success")
        else:
            self.result_label.config(text="❌ Files are DIFFERENT", bootstyle="danger")


# ---------------- Main Runner ----------------
if __name__ == "__main__":
    app = HashGeneratorApp()
    app.mainloop()
