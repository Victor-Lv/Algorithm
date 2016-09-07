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
		//�����ȸ�key���󿪱ٿռ�,�����޷�����������Կ�����²���(6F00)
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
		//p1ָ�����ܣ�0x02��or���ܣ�0x01��;
		//p2ָ������ģʽ��DES��byte 1��byte 8��
		//ע��command APDUд����ʮ������,Ҳ����10�㷨��apdu����Ҫд0a
		DESEngine = Cipher.getInstance(p2, false);
		
		//short b = myKey.getSize(); //����debug�鿴�ñ���ֵ
		//****** 2 *******��ʼ��������Կ�ͼ���ģʽ
		DESEngine.init(myKey, p1); // 2��ʾ����,1��ʾ����
	}
	
	public void GetResult(byte[] inBuf, short inOffset, short inLength, byte[] outBuf, short outOffset)
	{
		//****** 3 *******��������/���Ľ��м��ܲ��õ�����/����
		//�ر�ע��DES���ܽ����8�ı���,����outBuf���ٵĿռ�����ҪΪ8�ֽ�.����DES����ֻ�ܴ���8�ı����η�����������.����6F00
		DESEngine.doFinal(inBuf, inOffset, inLength, outBuf, outOffset);
	}
}

/**
 * DES--��Կ���ȹ̶���8bytes, 16 bytes for 2DES and 24 bytes for 3DES
 * 
 */