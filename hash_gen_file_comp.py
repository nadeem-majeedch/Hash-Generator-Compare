import hashlib
import os

def generate_hash(text, algorithm):
    """Generate a hash for a given text string using the selected algorithm."""
    encoded_text = text.encode()
    hasher = hashlib.new(algorithm)
    hasher.update(encoded_text)
    return hasher.hexdigest()

def generate_file_hash(filename, algorithm, chunk_size=4096):
    """Generate a hash for a given file using the selected algorithm."""
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

def compare_files(file1, file2, algorithm):
    """Compare two files based on their hash values."""
    hash1, err1 = generate_file_hash(file1, algorithm)
    hash2, err2 = generate_file_hash(file2, algorithm)

    if err1:
        return err1
    if err2:
        return err2

    print(f"\n🔹 Hash of {file1}: {hash1}")
    print(f"🔹 Hash of {file2}: {hash2}")

    if hash1 == hash2:
        return "✅ The files are identical (hashes match)."
    else:
        return "❌ The files are different (hashes do not match)."

def main():
    print("🔒 Universal Hash Generator & File Comparator 🔒")
    print("Select Mode:")
    print("1. Hash a String")
    print("2. Hash a File")
    print("3. Compare Two Files")

    mode = input("Enter your choice (1/2/3): ")

    print("\nSelect Hash Algorithm:")
    print("1. MD5")
    print("2. SHA1")
    print("3. SHA224")
    print("4. SHA256")
    print("5. SHA384")
    print("6. SHA512")

    algorithms = {
        "1": "md5",
        "2": "sha1",
        "3": "sha224",
        "4": "sha256",
        "5": "sha384",
        "6": "sha512"
    }

    choice = input("Enter your choice (1-6): ")
    algorithm = algorithms.get(choice, None)

    if not algorithm:
        print("❌ Invalid algorithm choice!")
        return

    # Mode 1: Hash a string
    if mode == "1":
        text = input("\nEnter text to hash: ")
        hash_value = generate_hash(text, algorithm)
        print(f"\n🔹 Algorithm: {algorithm.upper()}")
        print(f"🔹 Input Text: {text}")
        print(f"🔹 Hash Code: {hash_value}")

    # Mode 2: Hash a single file
    elif mode == "2":
        filename = input("\nEnter the file path: ")
        hash_value, error = generate_file_hash(filename, algorithm)
        if error:
            print(error)
        else:
            print(f"\n🔹 Algorithm: {algorithm.upper()}")
            print(f"🔹 File: {filename}")
            print(f"🔹 Hash Code: {hash_value}")

    # Mode 3: Compare two files
    elif mode == "3":
        file1 = input("\nEnter path of first file: ")
        file2 = input("Enter path of second file: ")
        result = compare_files(file1, file2, algorithm)
        print(f"\n🔍 Comparison Result: {result}")

    else:
        print("❌ Invalid mode selected!")

if __name__ == "__main__":
    main()
