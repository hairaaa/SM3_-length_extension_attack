# SM3_-length_extension_attack

SM3与长度扩展攻击：

参考资料：

https://github.com/hjzin/SM3LengthExtensionAttack/blob/master/%E5%AE%9E%E9%AA%8C%E6%96%87%E6%A1%A3.md

这个代码有问题为解决

在使用参考资料里的思路进行操作时：

![image](https://user-images.githubusercontent.com/104775629/181994866-2a85e383-48e2-48b9-9a69-727528def680.png)

但后来经过对参考资料里的代码进行的研究，发现其中有错误但答案却正确。

改变思路去改了代码，但未得到想要的结果。

我思路下的代码为：

#猜测hash值：使用已知的secret的长度拓展出一个分组，后加上附加信息，在上一个hash值的V代替了IV的情况下进行操作

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
    
    
#用于在新的message下计算出padding并在后面添加上附加信息  
  
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
     
#这里需注意IV的替换与少一轮迭代

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
