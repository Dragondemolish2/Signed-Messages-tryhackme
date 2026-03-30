<img width="1456" height="727" alt="Screenshot 2026-03-30 180321" src="https://github.com/user-attachments/assets/b8739546-fbc2-4ee3-9640-6f4c5181885b" />

<img width="699" height="811" alt="Screenshot 2026-03-30 180956" src="https://github.com/user-attachments/assets/1749424d-90a1-4a7c-aec5-9edd8aadf59f" />

We sign into the site and we start to poke around but find nothing of intrest so we try the great method of ffuf to find something odd.

<img width="803" height="543" alt="Screenshot 2026-03-30 182129" src="https://github.com/user-attachments/assets/152943d8-cc98-410d-922a-0b12507abb3b" />

FFuf eventully leads us to a page that was left behind which could show us something.

<img width="1325" height="788" alt="Screenshot 2026-03-30 182136" src="https://github.com/user-attachments/assets/b83ed730-74b6-43a3-8554-2805efdd23fd" />

We find something but I did not know where to go from there so I googled and a Medium article from Corlis showed to use a cryptographic script to get the flag.

<img width="840" height="634" alt="Screenshot 2026-03-30 182213" src="https://github.com/user-attachments/assets/9124d5d5-42be-40ee-b675-2027edcc17b2" />

Thank you to Corlis for the script I was lost at that point.


import hashlib
from sympy import nextprime
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

# Define the target parameters
user_identifier = b"USERNAME"
payload = b"MESSAGE"

# --- STEP 1: Predictable Prime Derivation ---
base_seed = user_identifier + b"_lovenote_2026_valentine"

# Calculate the first prime
hash_val_p = hashlib.sha256(base_seed).hexdigest()
prime_one = nextprime(int(hash_val_p, 16))

# Calculate the second prime
hash_val_q = hashlib.sha256(base_seed + b"pki").hexdigest()
prime_two = nextprime(int(hash_val_q, 16))

# --- STEP 2: Rebuild the RSA Key ---
modulus = prime_one * prime_two
pub_exp = 65537
totient = (prime_one - 1) * (prime_two - 1)
priv_exp = pow(pub_exp, -1, totient)

forged_rsa_key = RSA.construct((modulus, pub_exp, priv_exp))

# --- STEP 3: Handle the PSS Padding Collision ---
# A 512-bit key gives us 64 bytes of space.
# We must manually restrict the salt size so the signature fits inside the key.
modulus_bits = forged_rsa_key.size_in_bits()
encoded_message_len = (modulus_bits - 1 + 7) // 8

hash_obj = SHA256.new(payload)
hash_byte_len = hash_obj.digest_size

# Available Salt = Total Space - Hash Size - 2 padding bytes
available_salt_space = encoded_message_len - hash_byte_len - 2

# --- STEP 4: Sign and Output ---
pss_signer = pss.new(forged_rsa_key, salt_bytes=available_salt_space)
final_sig = pss_signer.sign(hash_obj)

print(f"Sender Username: {user_identifier.decode()}")
print(f"Message Content: {payload.decode()}")
print(f"Hex Signature:\n{final_sig.hex()}")
