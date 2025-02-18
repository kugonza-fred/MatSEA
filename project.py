import numpy as np
import secrets
import sys
import base64
import math
import string

'''
DESCRIPTION
MatSEA is an encryption algorithm that uses matrices to diffuse and confuse the plaintext into ciphertext.
On a highlevel, it splits plaintext into chunks which are then turned into matrices (plaintext matrices) with
characters repesented by their ascii decimal number. The matrices are then encrypted through a series of matrix
operations under modulo 128 and also shuffled in an intermediate step during encryption in order to confuse and
diffuse the original plaintext matrix.
'''

def chunk_string(sentence:str, chunk_size:int):
    '''
    return a list of lists with sublists having chunk_size elements each
    if the sentence is not long enough, spaces are added as extra elements
    chunk_size MUST BE > OR = 4
    Example:
    chunk_string("HELLO", 4) -> [["H","E","L","L"],["O"," "," "," "]]
    '''

    if not isinstance(sentence, str):
        raise TypeError("Invalid input to chunk_string")
        
    chunks = []  # Initialize the list to hold all chunks

    # Iterate over the string in steps of n
    for i in range(0, len(sentence), chunk_size):
        # Extract the substring for the current chunk
        chunk = list(sentence[i:i+chunk_size])

        # If the current chunk is shorter than n, pad it with spaces
        if len(chunk) < chunk_size:
            chunk.extend([' '] * (chunk_size - len(chunk)))

        # Append the chunk to the list of chunks
        chunks.append(chunk)

    return chunks

def padding_chunks(chunk_list:list, size:int):
    """
    Returns a list of lists
    Adds lists until the parent list is divisible by size
    size MUST BE > OR = 4, the same used for all the other functions
    """
    while True:
        if len(chunk_list) % size != 0:
            chunk_list.append([32] * size) # 32 is the ascii code for ' '
        else:
            return chunk_list


def sub_chunks(padded_chunk_list:list, size:int):
    '''
    groups elements in a list into lists of sizes 'size'
    size MUST BE > OR = 4
    '''
    # am fixing the size to be 4, one can modify it to larger number
    #size = 4
    sub_chunk_list = []
    for i in range(0, len(padded_chunk_list), size):
        # Extract the current chunk
        chunk_list_element = padded_chunk_list[i:i + size]

        sub_chunk_list.append(chunk_list_element)

    return sub_chunk_list

def gen_matrix(n:int):
    """
    Generates a cryptographically random square matrix of size n
    n MUST BE > OR = 4
    The matrix has an odd determinant to ensure it is coprime with 128, the modulus
    """
    if not isinstance(n, int):
        raise TypeError("n must be an integer")
    attempts = 0
    while True:
        attempts += 1
        # generating matrices using secrets because it is cryptographically random and secure
        matrix = np.array([[secrets.choice(range(33, 127)) for _ in range(n)] for _ in range(n)], dtype=int)

        # checking for odd determinants
        # This is because all odd numbers are coprime with 128, which is great for calculating multiplicative inverses
        det = int(round(np.linalg.det(matrix)))
        if det % 2 == 1:
            #print(f'attempts:{attempts}')
            return matrix

        else:
            continue  # Continue generating a new matrix

def gen_key(size:int):
    '''
    Generates square matrices B, R1, R2, K1, K2 of size size
    Returns a tuple (B, R1, R2, K1, K2 n) where n is the size
    '''
    if not isinstance(size, int):
        raise TypeError("The size 'n' should be an integer")
    B =  gen_matrix(size)
    R1 = gen_matrix(size)
    R2 = gen_matrix(size)
    K1 = gen_matrix(size)
    K2 = gen_matrix(size)
    n = size

    return B, R1, R2, K1, K2, n

def to_matrix(text:str, size:int):
    '''
    Returns a tuple of arrays ,i.e, square matrices of size size
    The elements of the matrix are ascii decimal numbers of each of the characters in the string
    '''

    # split string into lists of length size
    chunk_text = chunk_string(text, size)

    # convert the individial elements to their corresponding ascii decimal numbers
    chunk_ascii = [[ord(char) for char in sublist] for sublist in chunk_text]

    # add some padding (placeholder spaces) inform of empty lists
    chunk_ascii = padding_chunks(chunk_ascii, size)

    final_ascii_list = np.array(sub_chunks(chunk_ascii, size))

    return final_ascii_list


def to_text(matrix:np.ndarray):
    '''
    Returns a string from matrix
    maps each number in the matrix to the equivalent ascii character
    '''
    decoded_list = []
    for row in matrix:
        decoded_row = [chr(char) for char in row ]
        decoded_list.append(decoded_row)

    sentence = ''.join([''.join(sublist) for sublist in decoded_list])

    return sentence

#----------------------#
# DECRYPTION FUNCTIONS #
#----------------------#

def extended_euclidean(a:int, n:int):
    '''
    Extended euclidean algorithm
    Returns a tuple of (gcd, inverse), where inverse is the multiplicative inverse of a modulo n.
    Inverse will always exist because am using modulo 128 and a is the determinant of a carefully generated matrix by function gen_matrix() to ensure gcd is 1 (a and n are coprime)
    '''
    # Initializing variables
    old_r, r = a, n
    old_s, s = 1, 0
    old_t, t = 0, 1

    # Looping to apply the Euclidean algorithm
    while r != 0:
        quotient = old_r // r

        # Updating remainders and coefficients
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    # The GCD is old_r, and old_s is the multiplicative inverse (if gcd is 1)
    return old_r, old_s

def matrix_cofactors(M:np.ndarray):
    '''
    Returns a matrix as numpy.ndarray
    The matrix is a cofactor matrix, a step in calculating the inverse of a matrix under a given modulus
    '''
    cofactor_matrix = np.zeros(M.shape, dtype=int)
    for i in range(M.shape[0]):
        for j in range(M.shape[1]):
            # creating a minor matrix by deleting the ith row and jth column
            minor = np.delete(np.delete(M, i, axis=0), j, axis=1)

            #computing determinant of the minor matrix
            minor_det = int(round(np.linalg.det(minor)))

            # calculating the cofactor and ensuring the correct cofactor sign (+ve and -ve)
            cofactor = ((-1) ** (i + j)) * minor_det

            # adding the cofactor as an entry to the cofactor_matrix
            cofactor_matrix[i, j] = cofactor

    return cofactor_matrix


def mat_inv_mod(matrix:np.ndarray, modulus:int):

    # calculating the adjugate matrix
    adjugate = np.transpose(matrix_cofactors(matrix) % modulus)

    det = int(round(np.linalg.det(matrix)))

    gcd, det_inv = extended_euclidean(det, modulus)
    # calculating the final inverse of the matrix, under modulo mudulus

    inverse = det_inv * adjugate % modulus

    return inverse


def unshuffle_matrix(M):
    if not isinstance(M, np.ndarray):
        raise TypeError("Input must be a NumPy ndarray.")

    unshuffle = M.copy()
    # swapping back the columns first, 2nd and 4th
    unshuffle[:, [1, 3]] = unshuffle[:, [3, 1]]

    # swapping back the rows next, 1st and 3rd rows
    unshuffle[[0, 2], :] = unshuffle[[2, 0], :]

    return unshuffle



def decrypt_cipher_text(cipher_text: str, key: tuple) -> str:
    """
    Deserializes the Base64 encoded ciphertext blocks and decrypts them.
    The resulting plaintext matrices are converted back to text using to_text().
    """
    B, R1, R2, K1, K2, n = key

    pad_len = compute_pad_length(n)

    block_byte_count = n * n

    # First, breaking the ciphertext string into its constituent blocks.
    block_encoded_length = math.ceil(block_byte_count / 3) * 4

    plain_text = ''
    # Processing each block sequentially.
    for i in range(0, len(cipher_text), block_encoded_length):
        block_str = cipher_text[i:i + block_encoded_length]
        # Restore the proper '=' padding by replacing the last pad_len characters.
        block_str = restore_padding(block_str, pad_len)
        # Deserialize the Base64 string back into an n x n matrix.
        block = deserialize_matrix_base64(block_str, n)
        # Decrypt the matrix block.
        decrypted_matrix = decrypt(block, B, R1, R2, K1, K2)
        # Convert the matrix back into text.
        plain_text += to_text(decrypted_matrix)

    return plain_text


def decrypt(C, B, R1, R2, K1, K2):
    # Compute inverses
    B_inv = mat_inv_mod(B, 128)
    R1_inv = mat_inv_mod(R1, 128)
    R2_inv = mat_inv_mod(R2, 128)

    # compute
    # 1. X1 = ((C * R2^-1) - K2) * B^-1
    temp = np.mod(C @ R2_inv, 128)
    temp = np.mod(np.subtract(temp, K2), 128)
    X1 = np.mod(temp @ B_inv, 128)

    #2. Unshuffle the matrices
    X0 = unshuffle_matrix(X1)

    # PLAIN TEXT P = ((X0 * R1^-1) - K1) * B^-1
    temp2 = np.mod(X0 @ R1_inv, 128)
    temp2 = np.mod(np.subtract(temp2, K1), 128)
    P = np.mod(temp2 @ B_inv, 128)

    return P


#----------------------#
# ENCRYPTION FUNCTIONS #
#----------------------#
def shuffle_matrix(M:np.ndarray):
    """
    Returns a shuffled matrix
    M must have a min dimension of 4 by 4 i.e M.shape == (4,4)
    Shuffles by swapping row 1 with row 3, then column 2 and column 4
    Raises ValueError if matrix is not at least 4 x 4
    """

    # creating a copy to avoid changing the original
    shuffle = M.copy()

    if shuffle.shape[0] < 4 or shuffle.shape[1] < 4:
        raise ValueError("Matrix should have size of atleast 4")

    # swapping first row with 3rd row
    shuffle[[0, 2], :] = shuffle[[2, 0], :]
    # swapping second column with 4th column
    shuffle[:, [1, 3]] = shuffle[:, [3, 1]]

    return shuffle



def encrypt_plain_text(plain_text: str, key: tuple) -> str:
    """
    Encrypts plain_text using the provided key.
    Instead of converting each ciphertext matrix to text via to_text(),
    we serialize each block using Base64 and concatenate the results.
    Hide the trailing "=" padding (using a random replacement) based on n.
    """
    B, R1, R2, K1, K2, n = key

    pad_len = compute_pad_length(n)

    # Convert the plain text into a series of n x n matrices.
    text_matrices = to_matrix(plain_text, n)
    cipher_blocks = []
    for block in text_matrices:
        # Encrypt each block.
        C = encrypt(block, B, R1, R2, K1, K2)

        encode = serialize_matrix_base64(C)

        # hiding the '=' and replacing it with a random string

        encode = hide_padding(encode, pad_len)

        cipher_blocks.append(encode)

    return ''.join(cipher_blocks)



def encrypt(P, B, R1, R2, K1, K2):
    # encrypt by;
    # Step 1: X0 = (P*B + K1) * R1 mod 128
    temp = np.mod(P @ B, 128)
    temp = np.mod(np.add(temp,K1), 128)
    X0 = np.mod(temp @ R1, 128)

    # step 2: shuffle XO -> X1
    X1 = shuffle_matrix(X0)

    # Step 3: Cipher matrix C = (X1*B + K2) * R2 mod 128
    temp2 = np.mod(X1 @ B, 128)
    temp2 = np.mod(np.add(temp2, K2), 128)

    C = np.mod(temp2 @ R2, 128)

    return C

#######################################################
# ---------- Base64 Serialization Functions ----------#
#######################################################

def serialize_matrix_base64(matrix: np.ndarray) -> str:
    """
    Serializes a single n x n matrix into a Base64 encoded string.
    The matrix is cast to uint8 (its values are 0–127), flattened, and then encoded.
    """
    matrix_uint8 = matrix.astype(np.uint8) # converting all elements into 8 bit integers

    # encoding bytes into base64 and converting them into a string
    return base64.b64encode(matrix_uint8.tobytes()).decode('ascii')


def deserialize_matrix_base64(s: str, n: int) -> np.ndarray:
    """
    Deserializes a Base64 encoded string back into an n x n matrix.
    The string is decoded into bytes, interpreted as uint8, reshaped,
    and then converted to int.
    """
    b = base64.b64decode(s)
    # creating 1 D array from bytes and then reshaping it into matrix
    arr = np.frombuffer(b, dtype=np.uint8)

    return arr.reshape((n, n)).astype(int)

'''
def serialize_ciphertext_blocks(blocks: list, n: int) -> str:
    """
    Serializes a list of ciphertext blocks (each an n x n matrix) into a single string.
    Each block is encoded using Base64 and the encoded strings are concatenated.
    """
    encoded_blocks = [serialize_matrix_base64(block) for block in blocks]
    return ''.join(encoded_blocks)


def deserialize_ciphertext_blocks(s: str, n: int) -> list:
    """
    Deserializes a concatenated Base64 string into a list of n x n matrices.
    It calculates the encoded length for each block (using Base64’s 3-to-4 ratio)
    and then splits the string accordingly.
    """
    block_byte_count = n * n

    block_encoded_length = math.ceil(block_byte_count / 3) * 4 # 4 is the number of characters for each block
    blocks = []
    for i in range(0, len(s), block_encoded_length):
        # splitting the string into each of the blocks length
        block_str = s[i:i + block_encoded_length]
        block = deserialize_matrix_base64(block_str, n)
        blocks.append(block)
    return blocks

'''
def serialize_key(key: tuple) -> str:
    """
    Serializes the key tuple (B, R1, R2, K1, K2, n) into a single string.
    The five matrices are each serialized to Base64 and concatenated.
    Then the size n is appended as a single character using chr(n + 33).
    """
    B, R1, R2, K1, K2, n = key

    pad_len = compute_pad_length(n)

    encoded_B = hide_padding(serialize_matrix_base64(B), pad_len)
    encoded_R1 = hide_padding(serialize_matrix_base64(R1), pad_len)
    encoded_R2 = hide_padding(serialize_matrix_base64(R2), pad_len)
    encoded_K1 = hide_padding(serialize_matrix_base64(K1), pad_len)
    encoded_K2 = hide_padding(serialize_matrix_base64(K2), pad_len)
    # Append the encoded n
    return encoded_B + encoded_R1 + encoded_R2 + encoded_K1 + encoded_K2 + chr(n + 33)


def deserialize_key(s: str) -> tuple:
    """
    Deserializes a key string back into the tuple (B, R1, R2, K1, K2, n).
    The last character represents n as chr(n + 33); it is removed and decoded.
    The remaining string is split into five equal parts (one per matrix).
    """
    # The last character encodes n.
    n_char = s[-1]
    n = ord(n_char) - 33

    matrices_str = s[:-1]
    matrix_encoded_length = math.ceil((n * n) / 3) * 4

    pad_len = compute_pad_length(n)

    if len(matrices_str) != 5 * matrix_encoded_length: #We know the key is made of 5 matrices
        raise ValueError("Invalid serialized key length for n = {}".format(n))

    #Assigning the different matrices by splitting via matrix encoded length
    encoded_B  = matrices_str[0 : matrix_encoded_length]
    encoded_R1 = matrices_str[matrix_encoded_length : 2 * matrix_encoded_length]
    encoded_R2 = matrices_str[2 * matrix_encoded_length : 3 * matrix_encoded_length]
    encoded_K1 = matrices_str[3 * matrix_encoded_length : 4 * matrix_encoded_length]
    encoded_K2 = matrices_str[4 * matrix_encoded_length : 5 * matrix_encoded_length]

    # Restore the proper padding for each block.
    encoded_B  = restore_padding(encoded_B, pad_len)
    encoded_R1 = restore_padding(encoded_R1, pad_len)
    encoded_R2 = restore_padding(encoded_R2, pad_len)
    encoded_K1 = restore_padding(encoded_K1, pad_len)
    encoded_K2 = restore_padding(encoded_K2, pad_len)

    # turning each string into its matrix
    B  = deserialize_matrix_base64(encoded_B, n)
    R1 = deserialize_matrix_base64(encoded_R1, n)
    R2 = deserialize_matrix_base64(encoded_R2, n)
    K1 = deserialize_matrix_base64(encoded_K1, n)
    K2 = deserialize_matrix_base64(encoded_K2, n)
    return (B, R1, R2, K1, K2, n)

def compute_pad_length(n: int) -> int:
    """
    Computes the expected number of '=' padding characters in the Base64 encoding
    of an n x n matrix (each matrix has n*n bytes).

    Base64 encoding converts each group of 3 bytes into 4 characters.
    If n*n mod 3 == 0, no padding is needed;
    if mod == 1, two '=' characters are added;
    if mod == 2, one '=' character is added.
    """
    remainder = (n * n) % 3
    if remainder == 0:
        return 0
    elif remainder == 1:
        return 2
    else:  # remainder == 2
        return 1

def hide_padding(encoded: str, pad_len: int) -> str:
    """
    If the encoded Base64 string ends with the expected padding of '=' characters,
    replace that padding with a random alphanumeric string of the same length.
    This hides the typical pattern of padding in Base64.
    """
    expected_pad = '=' * pad_len
    if pad_len > 0 and encoded.endswith(expected_pad):
        # Generate a random alphanumeric string of length pad_len using the secrets module.
        rand_str = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(pad_len))
        return encoded[:-pad_len] + rand_str
    return encoded

def restore_padding(encoded: str, pad_len: int) -> str:
    """
    Replaces the last pad_len characters of the encoded string with the proper '=' padding.
    """
    if pad_len > 0:
        return encoded[:-pad_len] + ('=' * pad_len)
    return encoded



def main():
    n = 4

    key1 = gen_key(n)
    if len(sys.argv) == 1 :
        plaintext = input("Enter text to encrypt: ")

        ciphertext = encrypt_plain_text(plaintext, key1)

        print(f"The cipher text is: {ciphertext}")

        string = serialize_key(key1)
        print(f"The key is {string}")
        print()
        # decrypting the cipher text

        decrypted_text = decrypt_cipher_text(ciphertext, key1)
        print(f"DECRYPTED TEXT: {decrypted_text}")
        with open("encrypted.txt", 'a') as file:
            file.write("CIPHER TEXT\n")
            file.write(f'{ciphertext}\n')
            file.write("\n")
            file.write("ENCRYPTION KEY\n")
            file.write(f"{string}\n")
            file.write("\n")
            file.write(f"{'#'*36}\n")
            file.write('\n')

    elif len(sys.argv) == 2:
        if sys.argv[1] == '-d':
            c_text = input("Enter the cipher text to be decrypted: ")
            key2 = input("Enter the decryption key: ")

            key2 = deserialize_key(key2)

            #n2 = key2[-1]
            plaintext2 = decrypt_cipher_text(c_text, key2)

            print(f"The decrypted text is: {plaintext2}")
        elif sys.argv[1] == '-e':
            p_text = input("Enter text to be encrypted: ")
            cy_text = encrypt_plain_text(p_text, key1)
            key_as_string = serialize_key(key1)
            print(f"The Cipher text is :\n {cy_text}")
            print(f"The encryption key is :\n {key_as_string}")
            with open("encrypted.txt", 'a') as file:
                file.write("CIPHER TEXT\n")
                file.write(f'{cy_text}\n')
                file.write("\n")
                file.write("ENCRYPTION KEY\n")
                file.write(f"{key_as_string}\n")
                file.write("\n")
                file.write(f"{'#'*36}\n")
                file.write("\n")
        else:
            sys.exit()

    else:
        sys.exit()

if __name__ == "__main__":
    main()
