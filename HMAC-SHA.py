import hmac
import hashlib


def jm_sha256(key, value):
    """
    sha256加密
    return:加密结果转成16进制字符串形式
    设原始消息为M，原始消息长度LM，消息块Mi，哈希初值H0，SHA-256常量K[0]~K[63]（自然数中前64个质数的立方根的小数部分，取前32-bit）。则SHA-256算法的加密步骤具体如下：
    a) 消息（M）预处理。在消息末尾进行添加一位“1”和t位“0”，使得：
    (L_M+t+1) mod 512=448,0≤t<512
    将LM表示为64位大端存储格式，并添加到M末尾，组成新的消息M^’；
    b) 分解。将M^'按照每块512-bit大小分解为Mi；
    c) 拓展Mi到64字：W[0]~W[63]。将Mi分解为16个32-bit的大端存储的字（word），存为W[0], …, W[15]，其余字由以下公式得到：
    W_t=σ_1 (W_(t-2))+W_(t-7)+σ_0 (W_(t-15))+W_(t-16)
    d) 迭代。进行64次加密循环即可完成一次迭代。加密过程如图4所示：ABCDEFGH这8个字最开始分别是8个哈希初值，之后按照图示规则进行更新；深蓝色方块是事先定义好的非线性逻辑函数；红色方块代表加法（若结果大于232，则进行一次mod 232运算）；Kt为SHA-256常量，Wt为本区块产生第t个word，0≤t<64；最后一次循环所产生的八段字符串合起来即是此区块对应到的散列字符串；
    """
    hsobj = hashlib.sha256(key.encode("utf-8"))
    hsobj.update(value.encode("utf-8"))
    return hsobj.hexdigest()


print(jm_sha256("snsd", "我是sha256加密"))
# 1c1b963b4af90a0685d071a281af8d721451763765be160664cb83d6da6c1d3b


def jm_md5(key, value):
    """
    md5加密
    return:加密结果转成16进制字符串形式
    """
    hsobj = hashlib.md5(key.encode("utf-8"))
    hsobj.update(value.encode("utf-8"))
    return hsobj.hexdigest()


print(jm_sha256("snsd", "我是md5加密"))
# fed0ad1f56d4fc52017a7bf32561845444eec1cdae7065ea8f6b37abf076756b


def hmac_sha256(key, value):
    """
    hmacsha256加密
    return:加密结果转成16进制字符串形式
    ①. 密钥填充。若密钥比SHA-256算法的分组长度B（512-bit）短，则需在末尾填充0，直到其长度达到单向散列函数的分组长度为止。若密钥比分组长度长，则要用SHA-256算法求出密钥的散列值，然后将这个散列值作为新的密钥；
    ②. 内部填充。将填充后的密钥与被称为ipad的序列进行异或运算，所形成的值为ipadkey。ipad是将00110110这一序列不断循环反复直到达到分组长度；
    ③. 与消息组合。将ipadkey与消息组合，也就是将ipadkey附加在消息的开头。
    ④. 计算散列值。将3的结果输入SHA-256函数，并计算出散列值。
    ⑤. 外部填充。将填充后的密钥与被称为opad的序列进行异或运算，所形成的值为opadkey。opad是将01011100这一序列不断循环反复直到达到分组长度。
    ⑥. 与散列值组合。将4的散列值拼在opadkey后面。
    ⑦. 计算散列值。将6的结果输入SHA-256函数，并计算出散列值，这个散列值就是最终的摘要内容。
    """
    message = value.encode('utf-8')
    return hmac.new(key.encode('utf-8'), message, digestmod=hashlib.sha256).hexdigest()


print(hmac_sha256("snsd", "我是hmacsha256加密"))
# db8b895abc88a59cf8776a233ee1457c7239380347ef4dca8e48bc88433167eb


def hmac_md5(key, value):
    """
    hmacmd5加密
    return:加密结果转成16进制字符串形式
    一般步骤：
    a) 在密钥k后面添加0，或者对密钥k用H（Hash函数）进行处理，创建一个字长为B的字符串（B为Hash函数的明文分组长度）；
    b) 将上一步生成的B字长的字符串ipad做异或运算；
    c) 将数据流m填充至第二步的结果字符串中；
    d) 用H作用于第三步生成的数据流；
    e) 将第一步生成的B字长字符串与 opad 做异或运算；
    f) 再将第四步的结果填充进第五步的结果中；
    g) 用H作用于第六步生成的数据流，输出最终结果。
    """
    message = value.encode('utf-8')
    return hmac.new(key.encode('utf-8'), message, digestmod=hashlib.md5).hexdigest()


print(jm_sha256("snsd", "我是hmacmd5加密"))
# e2f8b511b75e5955d251b601494c392fe536b860ff6f1fa8f2157bc88cff9b59

