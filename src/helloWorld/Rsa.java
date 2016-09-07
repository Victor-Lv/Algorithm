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
	
	//�ǶԳƼ����㷨��Ҫ����Կ�Ե���ʽ�洢��Կ����Կ˽Կ��������PublicKey��PrivateKey����
	  //��������publicKey��privateKey�ֿ�����[����Ϊ��Կ��˽Կ�����ɵ���ض����Ƕ����ģ�]
	private KeyPair keypair;
	
	public Rsa() 
	{
		//newһ����Կ�Զ���
		//�ڶ���������������Կ���ȵ�ͬʱ,�������������ĵĳ���(��Ϊ���ĳ���=��Կ����[ģ��])Ϊ512����,Ҳ����64�ֽ�,ת��ʮ�����Ʊ�ʾΪ40
		keypair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_512);//ֻ֧��������캯������KeyPair(PublicKey,PrivateKey)������쳣
		
		//���ú����Զ������������Կ��������Կ��˽Կ��
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
		//****** 3 *******�������Ľ��м��ܲ��õ�����
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

/* RSAע�����
 * 
 * 
 * ע��һ��
 * Ϊ�β������д�������Ķ��ܽ��ܣ�6F00����
 * ����ֻ���ñ��ε���Կ�����������ĸ�ʽ����ȥ���ܲ���no error
 * ������Ϊ�������ʲô��Կ���ܽ��ܱ��˵�����,�Ǿ�Υ���������㷨�ı�����ѽ!!!
 * 
 * 
 * ע�����
 * RSA�������ɵ���Կ����>=64bits��Ϊ64bits�ı���,�����㣬��genKeyPair�������Զ���ȫ��λ
 * 
 * ע������RSA�㷨���ɵ����ĵĳ��� = ��Կ�ĳ���,��������ע���dofinal�������������������Ĵ�С����̫С
 * 
 * ע���ģ�RSA���Ĵ�����ܣ����ȿ����⣨>=0��,�������Զ�padding��
 * 		    ���Ǵ�����ܵ����ı����� >= ��Կ����(��64�ֽ�)����Ϊ��Կ���ȵı���,�����ܳ��������ĳ���Ҳ�ǵ�����Կ����
 * 
 * */
