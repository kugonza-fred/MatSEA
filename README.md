# MatSEA - Modular Matrix Transforms & Shuffle Encryption Algorithm

### Description: 
MatSEA is an improved version of the Hill Cipher. It is a symmetric encryption algorithm that uses matrices to diffuse and confuse the plaintext into ciphertext.  

MatSEA encrypts plaintext by converting it into structured matrices and applying modular matrix operations along with a shuffle-based diffusion technique, making the original text significantly obfuscated. It uses carefully chosen cryptographically random key matrices and its encryption mathematical operations are under modulo 128 which enables efficient processing of printable ASCII characters. Decryption reverses the transformations through matrix inverses and structured unshuffling. The generated cipher text and key are serialized using base64 encoding to store and copy-paste encrypted data without encountering non-printable ASCII characters.

## **Disclaimer**  
This project was submitted as a Python project to Harvard's introduction to programming with Python - CS50P. **DO NOT SUBMIT THIS PROJECT AS YOUR OWN TO CS50P**  
MATSEA is a simple encryption algorithm and by no means immune to cryptanalysis.

