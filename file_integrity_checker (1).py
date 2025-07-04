
import os
import hashlib

def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        return f"Error: {e}"

def generate_file_hashes(directory):
    file_hashes = {}
    for root, dirs, files in os.walk(directory):
        for file in files:
            abs_path = os.path.join(root, file)
            hash_val = calculate_file_hash(abs_path)
            file_hashes[abs_path] = hash_val
    return file_hashes

if __name__ == "__main__":
    folder = input("Enter folder path to scan: ")
    hashes = generate_file_hashes(folder)
    for path, hash_val in hashes.items():
        print(f"{path} : {hash_val}")
