
#from Cryptodome.Cipher import AES
import tkinter as tk
from tkinter import filedialog
#from Crypto.Cipher import AES
import os
import sys

# Main Application Window
root = tk.Tk()
root.title("File Data Secure Tool")
root.geometry("700x400")

# Notification Bar
notification_frame = tk.Frame(root, bg="lightgray")
notification_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=5)

notification_label = tk.Label(notification_frame, text="", font=("Arial", 10, "bold"), bg="lightgray")
notification_label.pack(pady=5)

def notify(message, message_type):
    """Display a notification message with a specific color."""
    # Choose color based on message type
    color = "blue" if message_type == "prompt" else "red" if message_type == "error" else "green"

    # Update notification label with the message and color
    notification_label.config(text=message, fg=color)

    # Auto-clear notification after 4 seconds
    root.after(5000, lambda: notification_label.config(text="", fg="black"))
    

# Encryption Functionality
def encrypt_file():
    def perform_encryption():
        
        file_path = file_entry.get()
        key = key_entry.get()
        if not file_path or not key:
            notify("Please upload a file and enter a key!", "error")
            return

        try:
            directory, original_name = os.path.split(file_path)
            base_name, ext = os.path.splitext(original_name)
            save_path = os.path.join(directory, f"{base_name}_encrypted{ext}.aes")

            cipher = AES.new(key.ljust(32)[:32].encode(), AES.MODE_EAX)
            with open(file_path, 'rb') as f:
                data = f.read()
            ciphertext, tag = cipher.encrypt_and_digest(data)

            with open(save_path, 'wb') as f:
                f.write(cipher.nonce + tag + ciphertext)

            notify(f"File Data encrypted successfully! Saved as: {save_path}", "success")
        except Exception as e:
            notify(f"Encryption failed: {str(e)}", "error")

    encryption_window = tk.Toplevel(root)
    encryption_window.title("File Encryption")

    tk.Label(encryption_window, text="Upload File:").pack(pady=5)
    file_entry = tk.Entry(encryption_window, width=50)
    file_entry.pack(pady=5)
    tk.Button(encryption_window, text="Browse", command=lambda: file_entry.insert(0, filedialog.askopenfilename())).pack(pady=5)

    tk.Label(encryption_window, text="Enter passphrase/Encryption Key:").pack(pady=5)
    key_entry = tk.Entry(encryption_window, width=50, show="*")
    key_entry.pack(pady=5)

    tk.Button(encryption_window, text="Encrypt", command=perform_encryption).pack(pady=10)
    
    

# Decryption Functionality
def decrypt_file():
    def perform_decryption():
        file_path = file_entry.get()
        key = key_entry.get()
        if not file_path or not key:
            notify("Please upload an encrypted file and enter a key!", "error")
            return

        try:
            directory, original_name = os.path.split(file_path)
            base_name, ext = os.path.splitext(original_name)
            if base_name.endswith("_encrypted"):
                base_name = base_name.replace("_encrypted", "")
            save_path = os.path.join(directory, f"{base_name}_decrypted{ext}")

            with open(file_path, 'rb') as f:
                nonce, tag, ciphertext = f.read(16), f.read(16), f.read()
            cipher = AES.new(key.ljust(32)[:32].encode(), AES.MODE_EAX, nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)

            with open(save_path, 'wb') as f:
                f.write(data)

            notify(f"File Data decrypted successfully! Saved as: {save_path}", "success")
        except ValueError:
            notify("Decryption failed! Incorrect key or file!", "error")
        except Exception as e:
            notify(f"Decryption failed: {str(e)}", "error")

    decryption_window = tk.Toplevel(root)
    decryption_window.title("File Decryption")

    tk.Label(decryption_window, text="Upload Encrypted File:").pack(pady=5)
    file_entry = tk.Entry(decryption_window, width=50)
    file_entry.pack(pady=5)
    tk.Button(decryption_window, text="Browse", command=lambda: file_entry.insert(0, filedialog.askopenfilename())).pack(pady=5)

    tk.Label(decryption_window, text="Enter Decryption Key:").pack(pady=5)
    key_entry = tk.Entry(decryption_window, width=50, show="*")
    key_entry.pack(pady=5)

    tk.Button(decryption_window, text="Decrypt", command=perform_decryption).pack(pady=10)

# Restart Functionality
def restart_program():
    python = sys.executable
    os.execl(python, python, *sys.argv)

# Close Application
def close_application():
    notify("File Data Secure System is closing . !", "prompt")
    
    root.destroy()

# Main Interface
tk.Label(root, text="Welcome to File Data Secure Tool!", font=("Arial", 16)).pack(pady=10)
tk.Button(root, text="Encrypt File", width=20, command=encrypt_file).pack(pady=10)
tk.Button(root, text="Decrypt File", width=20, command=decrypt_file).pack(pady=10)
tk.Button(root, text="Restart", width=20, command=restart_program).pack(pady=10)
tk.Button(root, text="Close", width=20, command=close_application).pack(pady=10)
notify("Welcome to File Data Secure Tool. !", "prompt")



# Run Application
root.mainloop()
