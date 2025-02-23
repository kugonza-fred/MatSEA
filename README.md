# MatSEA - Modular Matrix Transforms & Shuffle Encryption Algorithm

<!--## **Disclaimer**  
This project was submitted as a Python project to Harvard's introduction to programming with Python - CS50P by **Kugonza Fred**. <span style = "color: red;"> **DO NOT SUBMIT THIS PROJECT AS YOUR OWN TO CS50P** </span>  
MATSEA is a simple encryption algorithm, an improved version of the Hill Cipher and by no means immune to cryptanalysis as cryptanalysts have not analysed it. -->
### Description: 
MatSEA is a symmetric encryption algorithm that uses matrices to diffuse and confuse the plaintext into ciphertext.  
MatSEA encrypts plaintext by converting it into structured matrices and applying modular matrix operations and a shuffle-based diffusion technique, making the original text significantly obfuscated. It uses carefully chosen cryptographically random key matrices and its encryption mathematical operations are under modulo 128 which enables efficient processing of printable ASCII characters. Decryption reverses the transformations through matrix inverses and structured unshuffling. The generated cipher text and key are serialized using base64 encoding to store and copy-paste encrypted data without encountering non-printable ASCII characters.

## Dependencies
The algorithm makes use of the following libraries:

### **PIP Installable Libraries:**
- **NumPy** (`pip install numpy`) - Used for matrix operations such as multiplication, determinants, and inverses.

### **Python Built-in Modules:**
- **secrets** - For generating cryptographically secure random matrices.
- **sys** - For handling command-line arguments.
- **base64** - For encoding serialized matrices.
- **math** - For mathematical operations such as modular arithmetic.
- **string** - For working with characters during padding manipulation.

## Running the Program
MatSEA can be executed in encryption or decryption mode using the command line. The main function `main()` provides an interactive mode where the user can enter text and receive the encrypted or decrypted output.

#### **Encryption:**
Run the program and enter plaintext when prompted. The program will generate a Base64-encoded ciphertext along with a key for decryption.
```py
python matsea.py
```
Alternatively, use:
```python
python matsea.py -e
```
This will prompt for plaintext, encrypt it and then and display both the encrypted text and the key.

#### **Decryption:**
Run the program with the `-d` flag in the commandline 
```py
python matsea.py -d
```
This will prompt you for the cipher text and then the encryption key. The program will then decrypt the cipher text based on the encryption key and then return the decrypted original plain text. 


## Detailed Description
MMatSEA is based on matrix operations. It is a symmetric encryption i.e, it uses just one private key. The key consists of cryptographically random generated matrices. This was achieved using the `secrets` module. The algorithm maps characters to their ASCII decimal values and executes all calculations under modulo 128.


### Mathematical background
The algorithm uses 5 randomly generated matrices $B$, $R_1$, $R_2$, $K_1$ and $K_2$, the other matrix $P$ that is derived from the plain text.

#### **<u>Encryption</u>**
It then encrypts in 3 steps as follows:  
1. Step 1 

    $X_0 = \Big((P.B)+ K_1\Big) * R_1 \text{ mod } 128$  

2. step 2 

    - Shuffle the resulting matrix $X_0$ by switching some rows i.e, row 1 with row 3 and then columns 2 and 4, this results in a new matrix $X_1$. **It is for this reason the minimum size of the matrices is 4** 

3. step 3

    $C = \Big((X_1.B)+ K_2\Big) * R_2 \text{ mod } 128$  

    The resulting matrix $C$ is then converted into the cipher text.  

#### **<u>Decryption</u>**
The algorithm decrypts as follows: 

1. step 1:  
First, the inverses of the matrices $B$, $R_1$ and $R_2$ are calculated as $B^{-1}$, $R_1^{-1}$ and $R_2^{-1}$  respectively under modulo 128.

It is important to note that these matrices have determinants that are coprime with 128 so that the multiplicative inverse under modulo 128 can be calculated. The coprime determinants are ensured during generation by generating only matrices with odd determinants.  
This is because all odd numbers are coprime with 128.

2. step 2:  

    $X_1 = \Big((C * R_2^{-1}) - K_2\Big) * B^{-1} \text{ mod } 128$

3. step 3:  
Unshuffle the resulting matrix $X_1$ by swapping column 2 and 4 and then rows 1 and 3, resulting in a new matrix $X_0$

4. step 4:  

    $P = \Big((X_0 * R_1^{-1}) - K_1 \Big) * B^{-1} \text{ mod } 128$  
    The resulting $P$ is then converted into the plain text which is the original message.

---
## License
This project is licensed under the MIT License.

## Author  

**Kugonza Fred**
---


