# Password Hashing

Secret keys used to encrypt or sign confidential data have to be chosen from a very large keyspace.

However, passwords are usually short, human-generated strings, making dictionary attacks practical.

Password hashing functions derive a secret key of any size from a password and salt.

  - The generated key has the size defined by the application, no matter what the password length is.
  - The same password hashed with the same parameters will always produce the same output.
  - The same password hashed with different salts will produce different outputs.
  - The function deriving a key from a password and salt is CPU intensive and intentionally requires a fair amount of memory. Therefore, it mitigates brute-force attacks by requiring a significant effort to verify each password.
  
Common use cases:

  - Password storage, or rather storing what it takes to verify a password without having to store the actual password.
  - Deriving a secret key from a password; for example, for disk encryption.
  
Sodium's high-level crypto_pwhash_* API currently leverages the Argon2id function on all platforms. This can change at any point in time, but it is guaranteed that a given version of libsodium can verify all hashes produced by all previous versions from any platform. Applications don't have to worry about backward compatibility.
