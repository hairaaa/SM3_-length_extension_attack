"""
    SM3长度扩展攻击
    1.随机生成一个message，算出message的hash值
    2.根据hash值推出第一次压缩之后各个寄存器里的值
    3.在message+padding之后附加一段消息，用上一步寄存器里的值作为IV去加密附加的那段消息，得到hash
    4.用sm3去加密secret+padding+m'，得到hash
    5.第3步和第4步得到的hash值应该相等
"""
from gmssl import sm3, func
import random
import struct

T = [0x79cc4519, 0x7a879d8a]

def random_hex(length):
    result =hex(random.randint(0,16**length)).replace('0x','').upper()
    if(len(result)<length):
        result ='0'*(length-len(result))+result
    return result


def Fill(message):
    m = bin(int(message,16))[2:]#转化为二进制，去掉0b
    while len(m)%4!=0:
        m='0'+m
    l_len=len(m)
    k_len=0
    m=m+'1'
    while (l_len +1+k_len)%512!=448:
        k_len+=1
    for i in range(0,k_len):
        m=m+'0'
    l=bin((len(message)-128)*4)[2:]
    while len(l)!=64:
        l='0'+l
    m=m+l
    m = hex(int(m,2))[2:]
    print("填充后的消息为:",m)
    return m

def Group(m):#分块：512bit一块==128个16进制
    n = len(m)/128
    M = []
    for i in range(int(n)):
        M.append(m[0+128*i:128+128*i])
    return M

def Expand(Message,n):#讲B扩展为132个字
    W = []#w0-w67
    W_ = []#w_0-w_63
    for j in range(16):
        W.append(int(Message[n][0+8*j:8+8*j],16))
    for j in range(16,68):
        W.append(P1(W[j-16]^W[j-9]^ROL(W[j-3],15))^ROL(W[j-13],7)^W[j-6])
    for j in range(64):
        W_.append(W[j]^W[j+4])
    return W,W_

def ROL(X,i):#左移运算
    i = i % 32
    return ((X<<i)&0xFFFFFFFF) | ((X&0xFFFFFFFF)>>(32-i))

def FF(X,Y,Z,j):
    if j>=0 and j<=15:
        return X ^ Y ^ Z
    else:
        return ((X & Y) | (X & Z) | (Y & Z))
def GG(X,Y,Z,j):
    if j>=0 and j<=15:
        return X ^ Y ^ Z
    else:
        return ((X & Y) | (~X & Z))
def P0(X):
    return X^ROL(X,9)^ROL(X,17)
def P1(X):
    return X^ROL(X,15)^ROL(X,23)
def T_(j):
    if j>=0 and j<=15:
        return T[0]
    else:
        return T[1]



def CF(V,M,i):
    A,B,C,D,E,F,G,H = V[i]
    W,W_ = Expand(M,i)
    for j in range(64):
        SS1 = ROL((ROL(A,12)+E+ROL(T_(j),j%32))%(2**32),7)
        SS2 = SS1 ^ ROL(A,12)
        TT1 = (FF(A,B,C,j)+D+SS2+W_[j])%(2**32)
        TT2 = (GG(E,F,G,j)+H+SS1+W[j])%(2**32)
        D = C
        C = ROL(B,9)
        B = A
        A = TT1
        H = G
        G = ROL(F,19)
        F = E
        E = P0(TT2)
    a,b,c,d,e,f,g,h = V[i]
    V_ = [a^A,b^B,c^C,d^D,e^E,f^F,g^G,h^H]
    return V_

def Iterate(M,IV):
    n = len(M)
    B = []
    for i in range(1,n):
        B.append(M[i])

    V = []
    V.append(IV)
    for i in range(n-1):
        V.append(CF(V,B,i))
    return V[n-1]

def random_hex(length):
    result =hex(random.randint(0,16**length)).replace('0x','').upper()
    if(len(result)<length):
        result ='0'*(length-len(result))+result
    return result


def guess_hash(old_hash,n,appand):
    mes=""
    for i in range(n):
        mes+='a'
    m = bin(int(mes, 16))[2:]
    m_len = len(m)
    if m_len % 512 == 0:
        return m + appand
    else:
        m += '1'
        while len(m) % 448 != 0:
            m += '0'
        l = bin(m_len)[2:]
        while len(l) != 64:
            l = '0' + l
    m=m+l
    mes = hex(int(m, 2))[2:]
    mes=mes+appand
    vectors = []
    # 将old_hash分组，每组8个字节, 并转换为整数
    for r in range(0, len(old_hash), 8):
        vectors.append(int(old_hash[r:r + 8], 16))
    IV=vectors
    m = Fill(mes)   #填充后消息
    M = Group(m)  #数据分组
    Vn=Iterate(M,IV) #迭代
    result = ''
    for x in Vn:
      result += (hex(x)[2:])
    return result


def padding(message,appand):
    #找到secret+padding+appand
    m=""
    m_len=len(message)*4
    if m_len%512==0:
        return m+appand
    else:
        m += '1'
        while len(m)%448!=0:
            m+='0'
        l = bin(m_len)[2:]
        while len(l) != 64:
            l = '0' + l

        m = message+ hex(int(m, 2))[2:] + hex(int(l, 2))[2:]
        return m+appand



if __name__ == '__main__':
    secret = '202000460015'
    secret_hash = sm3.sm3_hash(func.bytes_to_list(bytes(secret, encoding='utf-8')))
    secret_len = len(secret)
    append_m = "202000460015"  # 附加消息
    guesshash = guess_hash(secret_hash,secret_len,append_m)
    print("生成secrect")
    print("secret: "+secret)
    print("secret hash:" + secret_hash)
    print("附加消息:", append_m)
    print("-----------------------------------------------------")
    print("构造的hash值")
    print("hash_guess:" + guesshash)
    print("-----------------------------------------------------")


    new_message=padding(secret,append_m)
    new_hash = sm3.sm3_hash(func.bytes_to_list(bytes(new_message, encoding='utf-8')))
    print("验证攻击是否成功")
    print("计算hash(secret+padding+m')")
    print("new message: \n" + new_message)
    print("hash(new message):" + new_hash)
    if new_hash == guesshash:
        print("success!")
    else:
        print("fail..")