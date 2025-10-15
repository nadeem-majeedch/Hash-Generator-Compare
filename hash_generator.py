import hashlib

def generate_hash(text, algorithm):
    """
    Generate a hash for a given text using the selected algorithm.
    """
    # Convert the text to bytes
    encoded_text = text.encode()

    # Select the hash algorithm
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

def main():
    print("🔒 Hash Code Generator 🔒")
    text = input("Enter a string to hash: ")

    print("\nSelect Hash Algorithm:")
    print("1. MD5")
    print("2. SHA1")
    print("3. SHA224")
    print("4. SHA256")
    print("5. SHA384")
    print("6. SHA512")

    choice = input("Enter your choice (1-6): ")

    # Map user choice to algorithm name
    algorithms = {
        "1": "md5",
        "2": "sha1",
        "3": "sha224",
        "4": "sha256",
        "5": "sha384",
        "6": "sha512"
    }

    algorithm = algorithms.get(choice, None)

    if algorithm:
        hash_value = generate_hash(text, algorithm)
        print(f"\n🔹 Algorithm: {algorithm.upper()}")
        print(f"🔹 Input Text: {text}")
        print(f"🔹 Hash Code: {hash_value}")
    else:
        print("❌ Invalid choice! Please select a valid option.")

if __name__ == "__main__":
    main()
