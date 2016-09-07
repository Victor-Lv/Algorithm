package helloWorld;

//import Hello;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;


public class Hello extends Applet {
	//下面这些都是未分配空间的实例化！需要后面自己使用new关键字或者用getInstance函数分配空间！
	private Des des;
	private Aes aes;
	private Rsa rsa;
	private Sign mySign;
	private Hash hmac;
	byte[] result;  //存储加密或解密后的结果
	
	public Hello(){
		//所有new的都应该尽量在构造时完成，否则每次发送一句APDU命令它都会new一遍空间出来，导致空间浪费
		rsa = new Rsa();
		aes = new Aes();
		mySign = new Sign();
		des = new Des();
		hmac = new Hash();
		result = new byte[64];//此处开辟空间的大小(S)按：DES的空间S >= 明文/密文长度, RSA的S >= 密钥字节数(512比特长度的密钥为64字节)
	}
	
	/** 
	 * 代码风格改进一：
	 * 把case里面对每种INS的处理封装成函数放构造函数和install及process中间
	 * */
	private void handleDES(APDU apdu) throws ISOException
	{
		byte[] buf = apdu.getBuffer();
		apdu.setIncomingAndReceive();//读取data,必不可少
		byte p1 = buf[ISO7816.OFFSET_P1];
		/* 必须先手动输入DES密钥 */
		if(p1 == (byte)0) //设置密钥
		{
			des.setDESKey(buf, (short)5);
			des.getDESKey(buf, (short)ISO7816.OFFSET_CDATA);
			apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)8);
			return;	//注意要return才能不执行下面的代码
		}
		else if(p1 == (byte)1) //加密
		{
			if(!des.isKeyInitialized()) //未设置密钥
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			byte p2 = buf[ISO7816.OFFSET_P2]; //p2指定算法模式
			if(p2 < (byte)1 || p2 > (byte)7)	//p1能代表的算法仅7种
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			des.init(p1, p2);
		}
		else if(p1 == (byte)2)	//解密
		{
			if(!des.isKeyInitialized()) //未设置密钥
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			byte p2 = buf[ISO7816.OFFSET_P2];
			if(p2 < (byte)1 || p2 > (byte)7)	//p1能代表的算法仅7种
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			des.init(p1, p2);
		}
		else
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		des.init(buf[ISO7816.OFFSET_P1], buf[ISO7816.OFFSET_P2]);
		//****** 3 *******传入明文/密文进行DES加密并得到密文/明文
		des.GetResult(buf, (short)ISO7816.OFFSET_CDATA, (short)buf[ISO7816.OFFSET_LC], result, (short)0);
		Util.arrayCopyNonAtomic(result, (short)0, buf, (short)ISO7816.OFFSET_CDATA, (short)buf[ISO7816.OFFSET_LC]);
		apdu.setOutgoingAndSend((short)5, (short)buf[ISO7816.OFFSET_LC]);
	}
	
	private void handleRSA(APDU apdu) throws ISOException
	{
		byte[] buf = apdu.getBuffer();
		apdu.setIncomingAndReceive();//读取data
		if(buf[ISO7816.OFFSET_P1] == (byte)0x00)
			rsa.init(true);
		else
			rsa.init(false);
	
		rsa.GetResult(buf, (short)ISO7816.OFFSET_CDATA, (short)buf[ISO7816.OFFSET_LC], result, (short)0);
		Util.arrayCopyNonAtomic(result, (short)0, buf, (short)ISO7816.OFFSET_CDATA, (short)64);
		apdu.setOutgoingAndSend((short)5, (short)64);
	}
	
	private void handleSHA(APDU apdu) throws ISOException
	{
		byte[] buf = apdu.getBuffer();
		apdu.setIncomingAndReceive();//读取data
		byte p1 = buf[ISO7816.OFFSET_P1];
		hmac.Init(p1);  //首先根据p1参数来确定要用到哪种hash算法
		hmac.GetResult(buf, (short)ISO7816.OFFSET_CDATA, (short)buf[ISO7816.OFFSET_LC], result, (short)0);
		Util.arrayCopyNonAtomic(result, (short)0, buf, (short)ISO7816.OFFSET_CDATA, (short)64);
		apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)64);
	}
	
	private void handleAES(APDU apdu) throws ISOException
	{
		byte[] buf = apdu.getBuffer();
		apdu.setIncomingAndReceive();//读取data
		byte p1 = buf[ISO7816.OFFSET_P1];
		
		/* 必须先手动输入DES密钥 */
		if(p1 == (byte)0) //设置密钥
		{
			aes.setAESKey(buf, (short)5);
			aes.getAESKey(buf, (short)ISO7816.OFFSET_CDATA);
			apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)8);
			return;	//注意要return才能不执行下面的代码
		}
		else if(p1 == (byte)1) //加密
		{
			if(!aes.isKeyInitialized()) //未设置密钥
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			byte p2 = buf[ISO7816.OFFSET_P2]; //p2指定算法模式
			if((p2 != (byte)13) && (p2 != (byte)14) && ((p2 < (byte)18) || (p2 > (byte)27)))//p1能代表算法模式
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			aes.init(p1, p2);
		}
		else if(p1 == (byte)2)	//解密
		{
			if(!aes.isKeyInitialized()) //未设置密钥
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			byte p2 = buf[ISO7816.OFFSET_P2];
			if((p2 != (byte)13) && (p2 != (byte)14) && ((p2 < (byte)18) || (p2 > (byte)27)))//p1能代表算法模式
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			aes.init(p1, p2);
		}
		else
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		aes.init(buf[ISO7816.OFFSET_P1], buf[ISO7816.OFFSET_P2]);
		//****** 3 *******传入明文/密文进行DES加密并得到密文/明文
		aes.GetResult(buf, (short)ISO7816.OFFSET_CDATA, (short)buf[ISO7816.OFFSET_LC], result, (short)0);
		Util.arrayCopyNonAtomic(result, (short)0, buf, (short)ISO7816.OFFSET_CDATA, (short)buf[ISO7816.OFFSET_LC]);
		apdu.setOutgoingAndSend((short)5, (short)buf[ISO7816.OFFSET_LC]);
	}
	
	private void handleSIGN(APDU apdu) throws ISOException
	{
		byte[] buf = apdu.getBuffer();
		apdu.setIncomingAndReceive();//读取data
		short signLen = (short)0;
		if(buf[ISO7816.OFFSET_P1] == (byte)0x00) //p1 == 00 表示做签
		{
			mySign.init(true);
			signLen = mySign.sign(buf, (short)ISO7816.OFFSET_CDATA, (short)buf[ISO7816.OFFSET_LC], result, (short)0);
			Util.arrayCopyNonAtomic(result, (short)0, buf, (short)ISO7816.OFFSET_CDATA, signLen);
			apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, signLen);
		}
		else 	//表示验签
		{
			mySign.init(false);
			//需要apdu同时输入Message以及签名,所以用p2参数来切分开二者
			//short temp = (short)(lc - p2); //仅用作调试时观察值的变化
			boolean verifyIsPass = mySign.verify(buf, (short)ISO7816.OFFSET_CDATA, (short)buf[ISO7816.OFFSET_P2], buf, (short)(ISO7816.OFFSET_CDATA+buf[ISO7816.OFFSET_P2]), (short)(buf[ISO7816.OFFSET_LC] - buf[ISO7816.OFFSET_P2]));
			if(verifyIsPass)
				buf[ISO7816.OFFSET_CDATA] = (byte)0x00;
			else
				buf[ISO7816.OFFSET_CDATA] = (byte)0x01;
			apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)1);
		}
	}
	
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		
		new Hello().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}
		
		byte[] buf = apdu.getBuffer();
				
		switch (buf[ISO7816.OFFSET_INS]) {
		case (byte) 0x00:	//INS == 0x00 表明要用DES加密
			handleDES(apdu);
			break;	//一定要有break否则会继续进入switch循环
			
		case (byte) 0x01:	//INS == 0x01 表示要用RSA算法
			handleRSA(apdu);
			break;
			
		case (byte)0x02:	//Hash-SHA
			handleSHA(apdu);
			break;
			
		case (byte) 0x03:	//AES
			handleAES(apdu);
			break;
			
		case (byte)0x04:	//signature
			handleSIGN(apdu);
			break;
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
}


/**主文件注意事项：
 * 
 * 注意一：所有new的都应该尽量在构造时完成，否则每次发送一句APDU命令它都会new一遍空间出来，导致空间浪费
 * 
 * 注意二：加密/解密得到的result数组开辟空间的大小(S)按：
 * 			DES的空间S >= 明文/密文长度, RSA的S >= 密钥字节数(512比特长度的密钥为64字节)
 * 
 * 注意三：switch-case的每个case之后一定要有break否则会继续进入switch循环
 * 
 * 注意三：验签时因为需要同时传入原始消息以及签名，所以一段apdu命令需要包含了“消息+签名”
 *         所以注意lc的值等于lenOf(Message)+lenOf(sign)。
 *         同时,为了切分开这两种数据,我额外用到了p2参数。
 *         还有要注意的是p2和lc的值传进去的都是十六进制表达,Applet在收到apdu之后会把它们自动转成十进制表示(debug即可观察到),
 *         所以p2表达的是Message字节长度的十六进制表达,lc表达的是data部分的字节长度的十六进制表达,并不需要画蛇添足去转换成十进制再send
 * 
 * 代码风格改进三：实际项目开发时需要将Des.java等这些辅助文件全部集成到主Applet文件中        
 * 
 * */
