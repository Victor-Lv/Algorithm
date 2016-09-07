package helloWorld;
import javacard.framework.JCSystem;
import javacard.security.RandomData;

public class RandGenerator
{
	private byte[] temp;	//�������ֵ
	private RandomData random;
	private byte size;	//���������
	
	//���캯��
	public RandGenerator()
	{
		size = (byte)4;
		temp = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);
		//�൱����getInstance�Ķ�Ҫ�ȵ������������ȡ����ʵ������ʹ��������������Ȼ6F00
		random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
	}
	
	//����length���ȵ������������
	public final byte[] GenrateSecureRand(short length)
	{
		temp = new byte[length];
		//����4bit�������
		random.generateData(temp, (short)0, (short)length);
		return temp;
	}
	
	//�������������
	public final byte GetRandSize()
	{
		return size;
	}
}
