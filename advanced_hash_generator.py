# ======================================================
# File: advanced_hash_generator.py
# Author: Your Name
# Project: Hash Generator & File Comparator
# Description: Advanced hash generator and comparator
# ======================================================

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import os
import logging
import pyperclip

# Setup logger
logging.basicConfig(filename="hash_generator.log",
                    level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

# ================== Hash Functions =====================

def compute_hash_from_text(text, algorithm):
    try:
        hash_func = getattr(hashlib, algorithm)
        return hash_func(text.encode()).hexdigest()
    except Exception as e:
        logging.error(f"Error hashing text: {e}")
        return "Error computing hash."


def compute_hash_from_file(filepath, algorithm):
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


# ================== GUI Application =====================

class HashGeneratorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🔒 Advanced Hash Generator & Comparator")
        self.geometry("800x600")
        self.resizable(False, False)

        self.algorithms = sorted(hashlib.algorithms_guaranteed)
        self.setup_notebook()

    def setup_notebook(self):
        """Setup Tabs"""
        notebook = ttk.Notebook(self)
        notebook.pack(expand=True, fill="both", padx=10, pady=10)

        tab_text = ttk.Frame(notebook)
        tab_file = ttk.Frame(notebook)
        tab_compare = ttk.Frame(notebook)

        notebook.add(tab_text, text="🔠 Hash Text")
        notebook.add(tab_file, text="📁 Hash File")
        notebook.add(tab_compare, text="⚖️ Compare Files")

        self.create_text_tab(tab_text)
        self.create_file_tab(tab_file)
        self.create_compare_tab(tab_compare)

    # --------------------------------------------------
    # TAB 1: Hash Text
    # --------------------------------------------------
    def create_text_tab(self, tab):
        ttk.Label(tab, text="Enter Text to Hash:", font=("Arial", 12)).pack(pady=5)
        self.text_input = tk.Text(tab, height=5, width=80)
        self.text_input.pack(pady=5)

        self.algorithm_choice_text = ttk.Combobox(tab, values=self.algorithms, state="readonly", width=20)
        self.algorithm_choice_text.set("sha256")
        self.algorithm_choice_text.pack(pady=5)

        ttk.Button(tab, text="Generate Hash", command=self.generate_text_hash).pack(pady=5)
        ttk.Button(tab, text="Copy Hash", command=self.copy_hash_text).pack(pady=5)

        self.hash_output_text = tk.Text(tab, height=5, width=80, wrap="word", bg="#f4f4f4")
        self.hash_output_text.pack(pady=10)

    def generate_text_hash(self):
        text = self.text_input.get("1.0", tk.END).strip()
        algorithm = self.algorithm_choice_text.get()
        if not text:
            messagebox.showwarning("Warning", "Please enter text to hash.")
            return
        hash_value = compute_hash_from_text(text, algorithm)
        self.hash_output_text.delete("1.0", tk.END)
        self.hash_output_text.insert(tk.END, hash_value)

    def copy_hash_text(self):
        result = self.hash_output_text.get("1.0", tk.END).strip()
        if result:
            pyperclip.copy(result)
            messagebox.showinfo("Copied", "Hash copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No hash to copy.")

    # --------------------------------------------------
    # TAB 2: Hash File
    # --------------------------------------------------
    def create_file_tab(self, tab):
        ttk.Label(tab, text="Select File to Hash:", font=("Arial", 12)).pack(pady=5)

        file_frame = ttk.Frame(tab)
        file_frame.pack(pady=5)
        self.file_path_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_path_var, width=60).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_file).pack(side=tk.LEFT)

        self.algorithm_choice_file = ttk.Combobox(tab, values=self.algorithms, state="readonly", width=20)
        self.algorithm_choice_file.set("sha256")
        self.algorithm_choice_file.pack(pady=5)

        ttk.Button(tab, text="Generate File Hash", command=self.generate_file_hash).pack(pady=5)
        ttk.Button(tab, text="Copy Hash", command=self.copy_hash_file).pack(pady=5)

        self.hash_output_file = tk.Text(tab, height=5, width=80, wrap="word", bg="#f4f4f4")
        self.hash_output_file.pack(pady=10)

    def browse_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            self.file_path_var.set(filepath)

    def generate_file_hash(self):
        filepath = self.file_path_var.get()
        algorithm = self.algorithm_choice_file.get()
        if not os.path.exists(filepath):
            messagebox.showerror("Error", "Please select a valid file.")
            return
        hash_value = compute_hash_from_file(filepath, algorithm)
        self.hash_output_file.delete("1.0", tk.END)
        self.hash_output_file.insert(tk.END, hash_value)

    def copy_hash_file(self):
        result = self.hash_output_file.get("1.0", tk.END).strip()
        if result:
            pyperclip.copy(result)
            messagebox.showinfo("Copied", "Hash copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No hash to copy.")

    # --------------------------------------------------
    # TAB 3: Compare Files
    # --------------------------------------------------
    def create_compare_tab(self, tab):
        ttk.Label(tab, text="Compare Two Files:", font=("Arial", 12)).pack(pady=5)

        compare_frame1 = ttk.Frame(tab)
        compare_frame1.pack(pady=5)
        self.file1_var = tk.StringVar()
        ttk.Entry(compare_frame1, textvariable=self.file1_var, width=60).pack(side=tk.LEFT, padx=5)
        ttk.Button(compare_frame1, text="Browse File 1", command=lambda: self.browse_compare_file(self.file1_var)).pack(side=tk.LEFT)

        compare_frame2 = ttk.Frame(tab)
        compare_frame2.pack(pady=5)
        self.file2_var = tk.StringVar()
        ttk.Entry(compare_frame2, textvariable=self.file2_var, width=60).pack(side=tk.LEFT, padx=5)
        ttk.Button(compare_frame2, text="Browse File 2", command=lambda: self.browse_compare_file(self.file2_var)).pack(side=tk.LEFT)

        self.algorithm_choice_compare = ttk.Combobox(tab, values=self.algorithms, state="readonly", width=20)
        self.algorithm_choice_compare.set("sha256")
        self.algorithm_choice_compare.pack(pady=5)

        ttk.Button(tab, text="Compare Files", command=self.compare_files).pack(pady=5)

        self.compare_result_label = ttk.Label(tab, text="", font=("Arial", 12))
        self.compare_result_label.pack(pady=10)

    def browse_compare_file(self, var):
        filepath = filedialog.askopenfilename()
        if filepath:
            var.set(filepath)

    def compare_files(self):
        file1 = self.file1_var.get()
        file2 = self.file2_var.get()
        algorithm = self.algorithm_choice_compare.get()

        if not os.path.exists(file1) or not os.path.exists(file2):
            messagebox.showerror("Error", "Please select valid files for comparison.")
            return

        hash1 = compute_hash_from_file(file1, algorithm)
        hash2 = compute_hash_from_file(file2, algorithm)

        if hash1 == hash2:
            self.compare_result_label.config(text="✅ Files are IDENTICAL", foreground="green")
        else:
            self.compare_result_label.config(text="❌ Files are DIFFERENT", foreground="red")


# ================== Main Runner =====================
if __name__ == "__main__":
    app = HashGeneratorApp()
    app.mainloop()
