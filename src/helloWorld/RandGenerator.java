package helloWorld;
import javacard.framework.JCSystem;
import javacard.security.RandomData;

public class RandGenerator
{
	private byte[] temp;	//随机数的值
	private RandomData random;
	private byte size;	//随机数长度
	
	//构造函数
	public RandGenerator()
	{
		size = (byte)4;
		temp = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);
		//类当中有getInstance的都要先调用这个函数获取对象实例才能使用其他方法，不然6F00
		random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
	}
	
	//产生length长度的随机数并返回
	public final byte[] GenrateSecureRand(short length)
	{
		temp = new byte[length];
		//生成4bit的随机数
		random.generateData(temp, (short)0, (short)length);
		return temp;
	}
	
	//返回随机数长度
	public final byte GetRandSize()
	{
		return size;
	}
}
