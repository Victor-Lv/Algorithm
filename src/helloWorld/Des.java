package helloWorld;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

public class Des
{
	private Cipher DESEngine;
	private DESKey myKey;
	
	Des()
	{
		//必须先给key对象开辟空间,否则无法进行设置密钥等往下操作(6F00)
		myKey = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
	}
	
	public void setDESKey(byte[] key, short keyOffset)
	{
		myKey.setKey(key, keyOffset);
		/*byte[] keyData = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		myKey.getKey(keyData, (short)0);*/ //just for debugging
	}
	
	public void getDESKey(byte[] keyData, short kOff)
	{
		myKey.getKey(keyData, kOff);
	}
	
	public boolean isKeyInitialized()
	{
		return myKey.isInitialized();
	}
	
	public void init(byte p1, byte p2)
	{
		//byte algorithm = p2; //just for debug checking
		//p1指定加密（0x02）or解密（0x01）;
		//p2指定加密模式（DES从byte 1到byte 8）
		//注意command APDU写的是十六进制,也就是10算法在apdu命令要写0a
		DESEngine = Cipher.getInstance(p2, false);
		
		//short b = myKey.getSize(); //可用debug查看该变量值
		//****** 2 *******初始化加密密钥和加密模式
		DESEngine.init(myKey, p1); // 2表示加密,1表示解密
	}
	
	public void GetResult(byte[] inBuf, short inOffset, short inLength, byte[] outBuf, short outOffset)
	{
		//****** 3 *******传入密文/明文进行加密并得到明文/密文
		//特别注意DES加密结果是8的倍数,所以outBuf开辟的空间至少要为8字节.并且DES解密只能处理8的倍数次方的密文输入.否则6F00
		DESEngine.doFinal(inBuf, inOffset, inLength, outBuf, outOffset);
	}
}

/**
 * DES--密钥长度固定用8bytes, 16 bytes for 2DES and 24 bytes for 3DES
 * 
 */