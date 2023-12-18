import hashlib
import secrets

def generate_password_from_string(input_string, length=12):
    """
    Generate a password based on the input string using cryptographic hashing.

    Parameters:
    - input_string (str): The input string (e.g., login).
    - length (int): The length of the generated password.

    Returns:
    - str: The generated password.
    """
    # Combine input string with a random salt
    salt = secrets.token_hex(16)
    combined_string = input_string + salt

    # Hash the combined string using SHA-256
    hashed_string = hashlib.sha256(combined_string.encode()).hexdigest()

    # Take the first 'length' characters of the hash as the password
    password = hashed_string[:length]
    
    return password

def save_password_to_file(password, file_name='password.txt'):
    """
    Save the generated password to a file.

    Parameters:
    - password (str): The password to save.
    - file_name (str): The name of the file to save the password.

    Returns:
    - str: Message indicating the success of password generation and saving.
    """
    with open(file_name, 'w') as file:
        file.write(password)

    return f"Password generated and saved successfully. Saved as '{file_name}'."

if __name__ == "__main__":
    # Example usage
    user_input = input("Enter the input string (e.g., login): ")
    generated_password = generate_password_from_string(user_input)
    
    file_name = input("Enter the name of the file to save the password (default 'password.txt'): ") or 'password.txt'
    result_message = save_password_to_file(generated_password, file_name)
    
    print(result_message)
