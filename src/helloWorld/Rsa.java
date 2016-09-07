package helloWorld;

import javacardx.crypto.Cipher;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Key;

public class Rsa 
{
	private Cipher RSAEngine;
	
	//非对称加密算法需要用密钥对的形式存储密钥（公钥私钥）：囊括PublicKey和PrivateKey对象
	  //而不能用publicKey、privateKey分开来存[是因为公钥和私钥的生成的相关而不是独立的？]
	private KeyPair keypair;
	
	public Rsa() 
	{
		//new一个密钥对对象
		//第二个参数决定了密钥长度的同时,决定了生成密文的长度(因为密文长度=密钥长度[模数])为512比特,也就是64字节,转成十六进制表示为40
		keypair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_512);//只支持这个构造函数，用KeyPair(PublicKey,PrivateKey)构造会异常
		
		//调用函数自动生成随机的密钥（包括公钥和私钥）
		keypair.genKeyPair();
		RSAEngine = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
	}
	
	public void init(boolean isEncryption)
	{
		if(isEncryption)
			RSAEngine.init(keypair.getPrivate(), Cipher.MODE_ENCRYPT);
		else
			RSAEngine.init(keypair.getPublic(), Cipher.MODE_DECRYPT);
	}
	
	public void GetResult(byte[] inBuf, short inOffset, short inLength, byte[] outBuf, short outOffset)
	{
		//****** 3 *******传入密文进行加密并得到密文
		RSAEngine.doFinal(inBuf, inOffset, inLength, outBuf, outOffset);
	}
	
	public Key GetPrivateKey()
	{
		return keypair.getPrivate();
	}
	
	public Key GetPublicKey()
	{
		return keypair.getPublic();
	}
}

/* RSA注意事项：
 * 
 * 
 * 注意一：
 * 为何不是所有传入的密文都能解密（6F00）？
 * 并且只有用本次的密钥产生过的密文格式传入去解密才能no error
 * 这是因为如果你拿什么密钥都能解密别人的密文,那就违背了密码算法的本意了呀!!!
 * 
 * 
 * 注意二：
 * RSA最终生成的密钥长度>=64bits且为64bits的倍数,若不足，则genKeyPair函数会自动补全到位
 * 
 * 注意三：RSA算法生成的密文的长度 = 密钥的长度,所以这里注意给dofinal函数传入的输出缓冲区的大小不能太小
 * 
 * 注意四：RSA明文传入加密，长度可随意（>=0）,函数会自动padding。
 * 		    但是传入解密的密文必须是 >= 密钥长度(如64字节)，且为密钥长度的倍数,最后解密出来的明文长度也是等于密钥长度
 * 
 * */
