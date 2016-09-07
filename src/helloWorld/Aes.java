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
		myKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false); //16bytes����Կ
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
		 * ����Ľ�����Cipher.MODE_ENCRYPT���������ȷ����p2ȷ��,Ϊ��ʡ�ռ��Ч����������ɹ���
		 */
		//short b = myKey.getSize(); //����debug�鿴�ñ���ֵ
		//p1ָ�����ܣ�0x02��or���ܣ�0x01��;
		//p2ָ������ģʽ���ʺ�AES-128�Ĵ�byte 13~byte 14 + ��byte 22 ~ byte 27��
		//ע��command APDUд����ʮ������,Ҳ����10�㷨��apdu����Ҫд0a
		//������㷨����ֻ֧��NOPAD,������ALG_AES_CBC_PKCS5���ᱨ6A80,Ϊʲô:��ΪJCOP���߲�֧�ָò���,�յ���Ƭ�Ϲ���û����
		AESEngine = Cipher.getInstance(p2, true);
		AESEngine.init(myKey, p1);
	}
	
	public void GetResult(byte[] inBuf, short inOffset, short inLength, byte[] outBuf, short outOffset)
	{
		AESEngine.doFinal(inBuf, inOffset, inLength, outBuf, outOffset);
	}
}

/*ע�����
 * 1.���getInstance�е��㷨ģʽѡ����NOPAD�Ļ������Ĵ���Ҳ����ﵽ>=��Կ����(��16�ֽ�)��Ϊ��Կ���ȵı���
 * 
 * 2.���Ĵ��뵱ȻҲ��DESһ��,���Ĳ������padding��,���Դ��볤����Ҫ>=��Կ����(��16�ֽ�)��Ϊ��Կ���ȵı���
 * 
 * 3.ΪɶgetInstance�е��㷨ģʽ�ܶ�ѡ��ѡ���˶��ᱨ0A80��:��ΪJCOP��֧������ģʽ���㷨
 * 
 */