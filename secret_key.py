import os

# Generate a random 24-byte (192-bit) key
secret_key = os.urandom(24)

# Print it as a string literal to be copied into your Flask app
# The output will look like b'\xaf\xf5\x1e...' - copy this entire string including the 'b'' prefix.
print(secret_key)