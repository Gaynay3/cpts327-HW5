import itertools
import string
from collections import Counter
import json

# Frequency of letters in English text
ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702, 'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966,
    'J': 0.153, 'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507, 'P': 1.929, 'Q': 0.095, 'R': 5.987,
    'S': 6.327, 'T': 9.056, 'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974, 'Z': 0.074
}
ALPHABET = string.ascii_uppercase

def caesar_decrypt(text, shift):
    decrypted = ""
    for char in text:
        if char in ALPHABET:
            decrypted += ALPHABET[(ALPHABET.index(char) - shift) % 26]
        else:
            decrypted += char
    return decrypted

def kasiski_examination(ciphertext):
    min_key_length = 2
    max_key_length = 10
    possible_lengths = []
    for key_len in range(min_key_length, max_key_length + 1):
        substrings = [ciphertext[i::key_len] for i in range(key_len)]
        avg_ic = sum(index_of_coincidence(sub) for sub in substrings) / key_len
        if avg_ic > 0.06:  # Close to English IoC
            possible_lengths.append(key_len)
    return possible_lengths

def index_of_coincidence(text):
    freqs = Counter(text)
    N = sum(freqs.values())
    ic = sum(f * (f - 1) for f in freqs.values()) / (N * (N - 1)) if N > 1 else 0
    return ic

def chi_squared(text):
    text_freqs = Counter(text)
    N = sum(text_freqs.values())
    chi_sq = sum(((text_freqs.get(letter, 0) / N - ENGLISH_FREQ[letter] / 100) ** 2) / (ENGLISH_FREQ[letter] / 100)
                 for letter in ALPHABET if N > 0)
    return chi_sq

def guess_key(ciphertext, key_length):
    key = ""
    for i in range(key_length):
        segment = ciphertext[i::key_length]
        best_shift = min(range(26), key=lambda shift: chi_squared(caesar_decrypt(segment, shift)))
        key += ALPHABET[best_shift]
    return key

def vigenere_decrypt(ciphertext, key):
    plaintext = ""
    key_repeated = itertools.cycle(key)
    for char in ciphertext:
        if char in ALPHABET:
            shift = ALPHABET.index(next(key_repeated))
            plaintext += ALPHABET[(ALPHABET.index(char) - shift) % 26]
        else:
            plaintext += char
    return plaintext

def crack_vigenere(ciphertext):
    ciphertext = ciphertext.upper().replace(" ", "")
    key_lengths = kasiski_examination(ciphertext)
    if not key_lengths:
        key_lengths = [5]  # Default to a reasonable guess
    for key_length in key_lengths:
        key = guess_key(ciphertext, key_length)
        decrypted_text = vigenere_decrypt(ciphertext, key)
        return key, decrypted_text  # Return both the key and decrypted text
    return "Could not determine key.", ""

def process_json_file(file_path, output_file):
    """Read the JSON file, decrypt each message, and write results to a text file."""
    with open(file_path, "r") as file:
        data = json.load(file)
    
    messages = data.get("messages", [])
    
    with open(output_file, "w") as out_file:
        for msg in messages:
            ciphertext = msg.get("encrypt_text", "")
            if ciphertext:
                key, decrypted = crack_vigenere(ciphertext)
                out_file.write(f"Message ID: {msg['id']}\nKey: {key}\nDecrypted Text: {decrypted}\n\n")
                print(f"Processed message ID: {msg['id']} and saved the result.")
            else:
                print(f"Skipping message ID: {msg['id']}, no 'encrypt_text' found.")

# Example usage:
process_json_file("sqs_messages.json", "decrypted_results.txt")
