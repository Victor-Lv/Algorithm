/**
 * MessageDigest
 */
package helloWorld;

/**
 * @author lv.lang
 *
 */
import javacard.security.MessageDigest;

public class Hash {
	private MessageDigest HashEngine;
	
	public void Init(byte algorithm) { //ֱ�Ӵ�p1����ȷ���������㷨
		
		/**����֧�ֵ��㷨����-->getInstance()�ᵼ��6F00
		 3:MessageDigest.ALG_RIPEMD160
		 5:MessageDigest.ALG_SHA_384
		 6:MessageDigest.ALG_SHA_512
		 */
		HashEngine = MessageDigest.getInstance(algorithm, false);
		//HashEngine = MessageDigest.getInitializedMessageDigestInstance(MessageDigest.ALG_SHA, false);//ͬ������
		
	}
	
	public void GetResult(byte[] inBuf, short inOffset, short inLength, byte[] outBuf, short outOffset)
	{
		//sha-1������ժҪ����̶�Ϊ160bit[20bytes]
			//����sha��Ӧ��ժҪ�ֽ����ɲ鿴MessageDigest.ALG_������ע�ʹ���
		HashEngine.doFinal(inBuf, inOffset, inLength, outBuf, outOffset);
	}
}

/*
 * 1.HASH��sha��md5��ֻ�ǽ�ԭ�Ĳ���һ����ϢժҪ����������֤(ֻ������?ֻ��������ɶ�ô�)��Ϣ��������Ҳ���Ǽ��ԭ���Ƿ񱻴۸ġ�
 * 		Ҳ����˵hash�������Ǳ�֤����һ��ԭ�Ķ�ӦΨһ��hashֵ��
 *      ����sha/md5��Щ���Ǵ���Կ�Ĺ�ϣ,Ҳ����˵��ͬ��Կ��ͬ��ԭ�Ĳ�����hash�ֲ�ͬ!
 *      �������Թ��������Լ������һ����Ϣ����hashֵ������ȥ������Ҳ��"����ͨ"����Ϣ��hash��ȷ��
 *      ����������ǩ����hash�����ϣ�����Ҫ��֤��ݣ��Ǿ�����hashֵ֮����ϷǶԳ���Կ�ӽ��ܣ�
 * 
 * 2.sha-1������ժҪ����̶�Ϊ160bit[20bytes]�����Ҽ����������ԭ�Ĺ��̣���Ҳ�������padding
 * 
 * 3.��֣����˼����ٵ��Է���ÿ�κ̵ܶ�ͬ��Message�������õ���DigestҲ���ǹ̶�����
 */