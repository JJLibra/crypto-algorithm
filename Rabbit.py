def fibonacci_shift_decrypt(encrypted_text, fib_list):
    decrypted_text = ""
    for i, char in enumerate(encrypted_text):
        if char.isalpha():  # 只对字母字符进行解密
            shift = fib_list[i]  # 从预先计算的斐波那契数列表中获取偏移量
            char_code = ord(char)
            offset = 65 if char.isupper() else 97  # 大写字母和小写字母的ASCII码基点不同
            # 解密字符并添加到解密文本中
            decrypted_char = chr(((char_code - offset - shift) % 26) + offset)
            decrypted_text += decrypted_char
        else:
            decrypted_text += char  # 非字母字符保持不变
    return decrypted_text


# 预先计算的斐波那契数列表
fib_list = [1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987]
# 测试
encrypted_text = "hmcvxg_nsb_oabhd"
decrypted_text = fibonacci_shift_decrypt(encrypted_text, fib_list)
print("Decrypted Text:", decrypted_text)
