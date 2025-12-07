import hashlib  #create hash values
import itertools #create patterns
import string
from concurrent.futures import ThreadPoolExecutor #multi-threading
from tqdm import tqdm #progress bar
import argparse #help option 
from concurrent.futures import as_completed
from passlib.hash import (
    bcrypt,
    sha256_crypt,
    sha512_crypt,
    pbkdf2_sha256,
    pbkdf2_sha512,
    md5_crypt
)


hash_names = {
    'md5',
    'sha1',
    'sha224',
    'sha256',
    'sha384',
    'sha3_224',
    'sha3_256',
    'sha3_384',
    'sha3_512',
    'sha512'
}

passlib_names = {
     'bcrypt',
    'sha256_crypt',
    'sha512_crypt',
    'pbkdf2_sha256',
    'pbkdf2_sha512',
    'md5_crypt'
}

# Map passlib hash names to actual classes
passlib_map = {
    'bcrypt': bcrypt,
    'sha256_crypt': sha256_crypt,
    'sha512_crypt': sha512_crypt,
    'pbkdf2_sha256': pbkdf2_sha256,
    'pbkdf2_sha512': pbkdf2_sha512,
    'md5_crypt': md5_crypt
}

def generate_password (min_len,max_len,chars):
    for length in range (min_len, max_len + 1):
        for pwd in itertools.product (chars, repeat=length): #generate combination of pass as per length 
            yield''.join(pwd)
def check_hash(hash_fn,password,target_hash, use_passlib=False):
    if use_passlib:
        return hash_fn.verify(password, target_hash)
    else:
        return hash_fn(password.encode()).hexdigest() == target_hash #check password hash matches to target hash value

def crack_hash(hash, wordlist=None,hash_type='md5',min_len=0,max_len=0,characters=string.ascii_letters + string.digits, max_worker = 4):
    hash_fn = None
    use_passlib = False
    #---------HashLib----------#
    try:
        if hash_type in hash_names:
            hash_fn = getattr(hashlib,hash_type) #Check hash_type in Hashlib
            use_passlib = False
        else:
            raise AttributeError #Move to PassLib
    except AttributeError:
        pass  #Let's Try PassLib

    #------PassLib------------#
    if hash_fn is None:    #Hash_type not found in HashLib
        if hash_type in passlib_names:
            hash_fn = passlib_map[hash_type]
            use_passlib = True
        else:
            raise ValueError (
                f"[!] Invalid Hash Type : {hash_type}\n"
                f"Supported : {hash_names | passlib_names}"
            )
    print ("[+] Hash Function loaded :", hash_type)

    if wordlist:
        with open(wordlist,'r', encoding='latin-1', errors='ignore') as file:
            lines = file.readlines()
            total_lines = len(lines)
            print(f"[*] Cracking hash {hash} using {hash_type} in list of {total_lines} passwords")

            with ThreadPoolExecutor(max_workers=max_worker) as executor:
                futures = {executor.submit(check_hash,hash_fn,line.strip(),hash,use_passlib) : line for line in lines} #worker run fun and assign password to future
                for _ in tqdm(as_completed(futures),total=len(futures), desc="Cracking Password"): #check every future result + pbar
                    future = _
                    if future.result():
                        return futures[future].strip() #return password in new line 
    elif min_len > 0 and max_len > 0:
        total_combination = sum(len(characters) ** length for length in range (min_len,max_len + 1)) #calculating combination of password
        print (f"[*] Cracking Hash {hash} using {hash_type} with generated password of length from {min_len} to {max_len}. Total combination : {total_combination}")

        with ThreadPoolExecutor(max_workers=max_worker) as executor:
            futures=[]
            with tqdm(total=total_combination,desc="Generating and Cracking Hash") as pbar:
                for pwd in generate_password(min_len,max_len,characters):
                    future = executor.submit(check_hash,hash_fn,pwd,hash, use_passlib)
                    futures.append(future)
                    pbar.update(1)
                    if future.result():
                        return pwd
    return None

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Hash Cracker")
    parser.add_argument('hash', help='The hash to crack.')
    parser.add_argument('-w','--wordlist', help='The path to the wordlist.')
    parser.add_argument('-t','--hash_type', help='The hash to use', default='md5')
    parser.add_argument('-min','--min_length', type=int, help='The minimum length of password to generate.')
    parser.add_argument('-max','--max_length', type=int, help='The maximum length of password to generate.')
    parser.add_argument('-c', '--characters', help='The characters to use for password generation.')
    parser.add_argument('--max_workers', type=int, help='The maximum number of threads.')

    args = parser.parse_args()

    cracked_password = crack_hash(args.hash, args.wordlist, args.hash_type, args.min_length, args.max_length, args.characters, args.max_workers)

    if cracked_password:
         print(f"[+] Found password: {cracked_password}")
    else:
        print("[!] Password not found.")