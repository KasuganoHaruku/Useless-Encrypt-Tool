import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
import qrcode
from pyzxing import BarCodeReader

def create_rsa_pair(save_path,save_name):
    rsa = RSA.generate(2048)
    private_key = rsa.exportKey()
    public_key = rsa.publickey().exportKey()
    img = qrcode.make(public_key)
    img.save(save_path+save_name+'_public_key.png')
    with open(save_path+save_name+'_private_key.pem', 'wb')as f:
        f.write(private_key)
    with open(save_path+save_name+'_public_key.pem', 'wb')as f:
        f.write(public_key)
    
def get_key(key_file):
    with open(key_file) as f:
        data = f.read()
        key = RSA.importKey(data)
    return key

def encrypt_data(msg_file,key_file,save_path):
    with open(msg_file,encoding='utf-8') as f:
        msg = f.read()
    public_key = get_key(key_file)
    cipher = PKCS1_cipher.new(public_key)
    encrypt_text = base64.b64encode(cipher.encrypt(bytes(msg.encode("utf8"))))
    with open(save_path, 'wb')as f:
            f.write(encrypt_text)
    return encrypt_text.decode('utf-8')

def decrypt_data(encrypt_msg_file,key_file,save_path):
    with open(encrypt_msg_file) as f:
        encrypt_msg = f.read()
    private_key = get_key(key_file)
    cipher = PKCS1_cipher.new(private_key)
    back_text = cipher.decrypt(base64.b64decode(encrypt_msg), 0)
    with open(save_path, 'wb')as f:
        f.write(back_text)
    return back_text.decode('utf-8')

def read_qrcode(qr_path,qr_out_path):
    reader = BarCodeReader()
    results = reader.decode(qr_path)
    str_get = str(results[0].get('parsed'))
    str_g = str(str_get[2:-1])
    str_g = str_g.replace('\\n','\n')
    with open(qr_out_path, 'wb')as f:
            f.write(str_g.encode('utf-8'))



#create_rsa_pair('D:/GitHub/Useless-Encrypt-Tool/','final')
#encrypt_data('D:/GitHub/Useless-Encrypt-Tool/test.txt','D:/GitHub/Useless-Encrypt-Tool/final_public_key.pem','D:/GitHub/Useless-Encrypt-Tool/crypted_text.txt')
#decrypt_data('D:/GitHub/Useless-Encrypt-Tool/crypted_text.txt','D:/GitHub/Useless-Encrypt-Tool/final_private_key.pem','D:/GitHub/Useless-Encrypt-Tool/decrypted_text.txt')
#read_qrcode('D:/GitHub/Useless-Encrypt-Tool/final_public_key.png','D:/GitHub/Useless-Encrypt-Tool/qr_public_key.pem')
