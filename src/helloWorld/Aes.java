/**
 * AES
 */
package helloWorld;
import javacard.security.KeyBuilder;
import javacard.security.AESKey;
import javacardx.crypto.Cipher;

/**
 * @author lv.lang
 *
 */
public class Aes {
	private AESKey myKey;
	private Cipher AESEngine;
	/**
	 * 
	 */
	public Aes() {
		myKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false); //16bytes的密钥
	}
	
	public void setAESKey(byte[] key, short keyOffset)
	{
		myKey.setKey(key, keyOffset);
		
	}
	
	public void getAESKey(byte[] keyData, short kOff)
	{
		myKey.getKey(keyData, kOff);
	}
	
	public boolean isKeyInitialized()
	{
		return myKey.isInitialized();
	}
	
	public void init(byte p1, byte p2)
	{
		/**
		 * 代码改进三：Cipher.MODE_ENCRYPT这类参数的确定用p2确定,为了省空间和效率牺牲代码可观性
		 */
		//short b = myKey.getSize(); //可用debug查看该变量值
		//p1指定加密（0x02）or解密（0x01）;
		//p2指定加密模式（适合AES-128的从byte 13~byte 14 + 从byte 22 ~ byte 27）
		//注意command APDU写的是十六进制,也就是10算法在apdu命令要写0a
		//这里的算法参数只支持NOPAD,其他如ALG_AES_CBC_PKCS5都会报6A80,为什么:因为JCOP工具不支持该参数,烧到卡片上估计没问题
		AESEngine = Cipher.getInstance(p2, true);
		AESEngine.init(myKey, p1);
	}
	
	public void GetResult(byte[] inBuf, short inOffset, short inLength, byte[] outBuf, short outOffset)
	{
		AESEngine.doFinal(inBuf, inOffset, inLength, outBuf, outOffset);
	}
}

/*注意事项：
 * 1.如果getInstance中的算法模式选用了NOPAD的话，明文传入也必须达到>=密钥长度(如16字节)且为密钥长度的倍数
 * 
 * 2.密文传入当然也和DES一样,密文不会给你padding的,所以传入长度需要>=密钥长度(如16字节)且为密钥长度的倍数
 * 
 * 3.为啥getInstance中的算法模式很多选项选用了都会报0A80呢:因为JCOP不支持这种模式的算法
 * 
 */