import hashlib
import os

def generate_hash(text, algorithm):
    """
    Generate a hash for a given text string using the selected algorithm.
    """
    encoded_text = text.encode()

    if algorithm == "md5":
        return hashlib.md5(encoded_text).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(encoded_text).hexdigest()
    elif algorithm == "sha224":
        return hashlib.sha224(encoded_text).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(encoded_text).hexdigest()
    elif algorithm == "sha384":
        return hashlib.sha384(encoded_text).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(encoded_text).hexdigest()
    else:
        return "Invalid algorithm selected!"

def generate_file_hash(filename, algorithm, chunk_size=4096):
    """
    Generate a hash for a given file using the selected algorithm.
    Reads the file in chunks to support large files.
    """
    if not os.path.exists(filename):
        return "❌ File not found!"

    try:
        if algorithm == "md5":
            hasher = hashlib.md5()
        elif algorithm == "sha1":
            hasher = hashlib.sha1()
        elif algorithm == "sha224":
            hasher = hashlib.sha224()
        elif algorithm == "sha256":
            hasher = hashlib.sha256()
        elif algorithm == "sha384":
            hasher = hashlib.sha384()
        elif algorithm == "sha512":
            hasher = hashlib.sha512()
        else:
            return "❌ Invalid algorithm selected!"

        with open(filename, "rb") as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)

        return hasher.hexdigest()
    except Exception as e:
        return f"⚠️ Error reading file: {e}"

def main():
    print("🔒 Universal Hash Generator 🔒")
    print("Select Input Type:")
    print("1. Hash a String")
    print("2. Hash a File")

    mode = input("Enter your choice (1/2): ")

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

    if mode == "1":
        text = input("\nEnter text to hash: ")
        hash_value = generate_hash(text, algorithm)
        print(f"\n🔹 Algorithm: {algorithm.upper()}")
        print(f"🔹 Input Text: {text}")
        print(f"🔹 Hash Code: {hash_value}")

    elif mode == "2":
        filename = input("\nEnter the file path: ")
        hash_value = generate_file_hash(filename, algorithm)
        print(f"\n🔹 Algorithm: {algorithm.upper()}")
        print(f"🔹 File: {filename}")
        print(f"🔹 Hash Code: {hash_value}")

    else:
        print("❌ Invalid mode selected!")

if __name__ == "__main__":
    main()
