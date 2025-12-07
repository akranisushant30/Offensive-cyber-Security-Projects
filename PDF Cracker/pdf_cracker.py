import pikepdf #To Read, Edit, write PDF files
from tqdm import tqdm #progress bar
import itertools #combinatorial operation
import string 
from concurrent.futures import ThreadPoolExecutor # Threading

def password_generation (chars,min_len,max_len):
    for length in range (min_len, max_len + 1):
        for password in itertools.product(chars, repeat = length): #Generating Combination
            yield''.join(password) #convert tuple into string
def load_password(wordlist_file):
    with open (wordlist_file, 'r') as pfile:
        for line in pfile:
            yield line.strip() #remove \n 

def try_password (pdf_file,password):
    try:
        with pikepdf.open(pdf_file,password=password) as pdf: #try to open/decrypt pdf
            print("[+] Password found:", password)
            return password
    except:
        return None
def main_decryption(pdf_file,passwords,total_passwords,max_workers=4):
    with tqdm(total = total_passwords, desc="Description", unit="Password") as p_bar: 
        with ThreadPoolExecutor(max_workers=max_workers) as executor: #4 Threads works parallely 
            future_passwords = {executor.submit(try_password,pdf_file,pwd) : pwd for pwd in passwords}
            for future in tqdm(future_passwords,total=total_passwords):
                password = future_passwords[future]
                if future.result():
                    return future.result()
                p_bar.update(1)
    print("Unable to decrypt PDF. Password not found in the wordlist.")
    return None

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Decrypt a Password-Protected File") #provide --help
    parser.add_argument('pdf_file', help="Path to the Pdf File")
    parser.add_argument('-w', '--wordlist', help ='Path to the Passowrd file',default=None)
    parser.add_argument('-g', '--generate', action='store_true', help='Generate passwords on the fly') #brute-force mode
    parser.add_argument('-min','--min_length', type=int, help='Minimum length of passwords to generate', default=1)
    parser.add_argument('-max', '--max_length', type=int, help='Maximum length of passwords to generate', default=5)
    parser.add_argument('-c', '--charset', type=str, help='Characters to use for password generation', default=string.ascii_letters + string.digits + string.punctuation) 
    parser.add_argument('--max_workers', type=int, help='Maximum number of parallel threads', default=5)

    args = parser.parse_args()
    if args.generate:
        passwords = password_generation(args.charset, args.min_length, args.max_length)
        total_passwords = sum(1 for _ in password_generation(args.charset, args.min_length, args.max_length))
    elif args.wordlist:
        passwords = load_password(args.wordlist)
        total_passwords = sum(1 for _ in load_password(args.wordlist))
    else:
        print("Either --wordlist must be provided or --generate must be specified.")
        exit(1)
    decrypted_password = main_decryption(args.pdf_file, passwords, total_passwords, args.max_workers)
    if decrypted_password:
        print("PDF decrypted successfully with password:", decrypted_password)
    else:
        print("Unable to decrypt PDF. Password not found.")