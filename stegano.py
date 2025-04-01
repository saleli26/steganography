from PIL import Image
from cryptography.fernet import Fernet
import base64

# Générer une clé
def generate_key():
    key = Fernet.generate_key()
    print(f"Clé secrète (à conserver) : {key.decode()}")
    return key

# Fonction pour chiffrer un message
def encrypt_message(message, key):
    cipher = Fernet(key)
    encrypted_message = cipher.encrypt(message.encode())
    return base64.urlsafe_b64encode(encrypted_message).decode()

# Fonction pour déchiffrer un message
def decrypt_message(encrypted_message, key):
    cipher = Fernet(key)
    decrypted_message = cipher.decrypt(base64.urlsafe_b64decode(encrypted_message.encode()))
    return decrypted_message.decode()

# Fonction pour convertir un message en binaire
def message_to_binary(message):
    return ''.join(format(ord(char), '08b') for char in message)

# Fonction pour cacher un message dans une image
def hide_message(image_path, message, key, output_path):
    image = Image.open(image_path)
    pixels = list(image.getdata())
    
    encrypted_message = encrypt_message(message, key)
    encrypted_message += "##END##"  # Marqueur de fin
    binary_message = message_to_binary(encrypted_message)
    
    if len(binary_message) > len(pixels) * 3:
        raise ValueError("Message trop long pour être caché dans cette image.")
    
    new_pixels = []
    binary_index = 0
    
    for pixel in pixels:
        if binary_index < len(binary_message):
            new_pixel = list(pixel)
            for i in range(3):  # Modifier les 3 premières valeurs RGB
                if binary_index < len(binary_message):
                    new_pixel[i] = (new_pixel[i] & ~1) | int(binary_message[binary_index])
                    binary_index += 1
            new_pixels.append(tuple(new_pixel))
        else:
            new_pixels.append(pixel)
    
    new_image = Image.new(image.mode, image.size)
    new_image.putdata(new_pixels)
    new_image.save(output_path)
    print(f"Message caché dans {output_path}")

# Fonction pour extraire un message caché dans une image
def extract_message(image_path, key):
    image = Image.open(image_path)
    pixels = list(image.getdata())
    
    binary_message = ""
    for pixel in pixels:
        for i in range(3):
            binary_message += str(pixel[i] & 1)
    
    message = ""
    for i in range(0, len(binary_message), 8):
        char = chr(int(binary_message[i:i+8], 2))
        if message.endswith("##END##"):
            encrypted_message = message[:-6]  # Retirer le marqueur de fin
            return decrypt_message(encrypted_message, key)
        message += char
    
    return "Aucun message caché trouvé."

#main
if __name__ == "__main__":
    choice = input("Voulez-vous (1) générer une clé, (2) cacher un message ou (3) extraire un message ? ")
    if choice == "1":
        generate_key()
    elif choice == "2":
        img = input("Image source : ")
        msg = input("Message à cacher : ")
        key = input("Clé secrète : ").encode()
        output = input("Nom du fichier de sortie : ")
        hide_message(img, msg, key, output)
    elif choice == "3":
        img = input("Image contenant un message : ")
        key = input("Clé secrète : ").encode()
        print("Message extrait :", extract_message(img, key))
    else:
        print("Choix invalide.")
