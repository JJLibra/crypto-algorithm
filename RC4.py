import base64

def get_message():
    print("Enter your message:")
    s = input()
    return s

def get_key():
    print("Enter your key:")
    key = input()
    if key == '':
        key = 'None_public_key'
    return key

# 生成S盒
def init_box(key):
    s_box = list(range(256)) #我这里没管秘钥小于256的情况，小于256应该不断重复填充即可
    j = 0
    for i in range(256):
        j = (j + s_box[i] + ord(key[i % len(key)])) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]
    #print(type(s_box)) #for_test
    return s_box

# 加密/解密算法
def ex_encrypt(plain,box,mode):
    # 利用PRGA生成秘钥流并与密文字节异或
    if mode == '2':
        while True:
            c_mode = input("Enter your decryption mode:1.Base64 or 2.Ordinary\n")
            if c_mode == '1':
                plain = base64.b64decode(plain)
                plain = bytes.decode(plain)
                break
            elif c_mode == '2':
                plain = plain
                break
            else:
                print("Something Wrong,Please re-enter it.")
                continue

    res = []
    i = j = 0
    for s in plain:
        i = (i + 1) %256
        j = (j + box[i]) %256
        box[i], box[j] = box[j], box[i]
        t = (box[i] + box[j])% 256
        k = box[t]
        res.append(chr(ord(s)^k))

    cipher = "".join(res)
    if  mode == '1':
        # 化成可视字符需要编码
        print("Original ciphertext:")
        print(cipher)
        # base64的目的也是为了变成可见字符
        print("Base64 encoding:")
        print(str(base64.b64encode(cipher.encode('utf-8')),'utf-8'))
    if mode == '2':
        print("Plaintext:")
        print(cipher)

def get_mode():
    print("Choice:1. Encrypt 2. Decode")
    mode = input()
    if mode == '1':
        message = get_message()
        key = get_key()
        box = init_box(key)
        ex_encrypt(message,box,mode)
    elif mode == '2':
        message = get_message()
        key = get_key()
        box = init_box(key)
        ex_encrypt(message, box, mode)
    else:
        print("There is a mistake in the input!")

# 主函数，对合性，加密解密算法一致
while True:
    get_mode()


