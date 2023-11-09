"""
RSA加解密算法
2020.11.28
1.模平方算法   2.欧几里得算法   3.费马素性检测算法
"""
import random


def fastExpMod(b, n, m):
    """
    return : b^n mod m
    """
    result = 1
    # 重复平方算法（从右向左）
    while n != 0:
        if (n & 1) == 1:  # 按位与操作
            result = (result * b) % m
        b = (b * b) % m
        n = n >> 1  # 位数右移操作
    return result


def Euclid(a, b):
    """
    欧几里得算法 ax + by = gcd(a,b)
    Return : [x , y , gcd(a,b)]
    """
    X = [1, 0, a]
    Y = [0, 1, b]
    while Y[2] != 0:
        Q = X[2] // Y[2]
        NEW_Y = [i * Q for i in Y]
        T = list(map(lambda x: x[0] - x[1], zip(X, NEW_Y)))
        X = Y.copy()
        Y = T.copy()
    return X


def fermatPrimeTest(m, k):
    """
    费马素性检验算法
    m : 给定整数
    k : 安全参数，重复K次
    但可能出现费马伪素数，设置安全参数可以降低出现伪素数的概率
    """
    if m % 2 == 0:
        return False
    for i in range(k):
        a = random.randint(2, m - 2)
        g = Euclid(a, m)  # a*g[0] + m*g[1] = g[2](gcd(a,m))
        if g[2] == 1:  # g[2] == 1 说明 a 与 m 互素
            r = fastExpMod(a, m - 1, m)
            if r == 1:
                continue
            else:
                return False
        else:
            return False
    return True


def findPrime(lower, upper):
    """
    return : 一个位于upper和lower之间的素数
    """
    while True:
        n = random.randint(lower, upper)
        if fermatPrimeTest(n, 6):
            return n


def selectE(fn):
    """
    fn : euler function
    Return : e
    """
    while True:
        e = random.randint(1, fn)
        temp = Euclid(e, fn)
        if temp[2] == 1:
            return e


def keyGenerate(lower, upper):
    """
    给定两个素数p和q生成的区间
    return : e,n,d
    """
    # 生成 p, q
    p = findPrime(lower, upper)
    q = findPrime(lower, upper)
    # print("p:" + str(p) + "   q:" + str(q))
    # print("q:"+str(q))
    n = p * q
    fn = (p - 1) * (q - 1)
    e = selectE(fn)  # 随机生成一个与fn互素的公钥e
    temp = Euclid(e, fn)  # 欧几里得算法求逆元
    d = temp[0]
    if d < 0:  # 由于e和fn互素故一定存在逆元
        d = d + fn  # 保证d为正数
    return p, q, e, n, d, fn


def start():
    p, q, e, n, d, fn = keyGenerate(1000, 10000)  # 密钥生成
    # 更改keyGenerate函数的两个参数，可以改变生成素数的位数大小。
    print("\npublic key (e,n):\n", end="")
    print("(" + str(e) + ", " + str(n) + ")\n")
    print("private key (p,q,d,φ(n)):\n" + "(" + str(p) + ", " + str(q) + ", " + str(d) + ", " + str(fn) + ")\n")
    m = random.randint(1, n)  # m < n m为明文
    print("Plaintext: " + str(m))
    c = fastExpMod(m, e, n)  # 加密  c为密文 m^e mod n
    print("\nEncryption of PlainText: " + str(c))
    x = fastExpMod(c, d, n)  # 解密 c^d mod n
    print("\nDecryption of CipherText: " + str(x))
    if x == m:
        print("\nThe plaintext and ciphertext are the same.\nEncryption succeeded!")
    else:
        print("Encryption failed!")


if __name__ == "__main__":
    start()
