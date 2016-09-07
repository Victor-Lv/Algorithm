package helloWorld;

//import Hello;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;


public class Hello extends Applet {
	//������Щ����δ����ռ��ʵ��������Ҫ�����Լ�ʹ��new�ؼ��ֻ�����getInstance��������ռ䣡
	private Des des;
	private Aes aes;
	private Rsa rsa;
	private Sign mySign;
	private Hash hmac;
	byte[] result;  //�洢���ܻ���ܺ�Ľ��
	
	public Hello(){
		//����new�Ķ�Ӧ�þ����ڹ���ʱ��ɣ�����ÿ�η���һ��APDU����������newһ��ռ���������¿ռ��˷�
		rsa = new Rsa();
		aes = new Aes();
		mySign = new Sign();
		des = new Des();
		hmac = new Hash();
		result = new byte[64];//�˴����ٿռ�Ĵ�С(S)����DES�Ŀռ�S >= ����/���ĳ���, RSA��S >= ��Կ�ֽ���(512���س��ȵ���ԿΪ64�ֽ�)
	}
	
	/** 
	 * ������Ľ�һ��
	 * ��case�����ÿ��INS�Ĵ����װ�ɺ����Ź��캯����install��process�м�
	 * */
	private void handleDES(APDU apdu) throws ISOException
	{
		byte[] buf = apdu.getBuffer();
		apdu.setIncomingAndReceive();//��ȡdata,�ز�����
		byte p1 = buf[ISO7816.OFFSET_P1];
		/* �������ֶ�����DES��Կ */
		if(p1 == (byte)0) //������Կ
		{
			des.setDESKey(buf, (short)5);
			des.getDESKey(buf, (short)ISO7816.OFFSET_CDATA);
			apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)8);
			return;	//ע��Ҫreturn���ܲ�ִ������Ĵ���
		}
		else if(p1 == (byte)1) //����
		{
			if(!des.isKeyInitialized()) //δ������Կ
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			byte p2 = buf[ISO7816.OFFSET_P2]; //p2ָ���㷨ģʽ
			if(p2 < (byte)1 || p2 > (byte)7)	//p1�ܴ�����㷨��7��
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			des.init(p1, p2);
		}
		else if(p1 == (byte)2)	//����
		{
			if(!des.isKeyInitialized()) //δ������Կ
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			byte p2 = buf[ISO7816.OFFSET_P2];
			if(p2 < (byte)1 || p2 > (byte)7)	//p1�ܴ�����㷨��7��
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			des.init(p1, p2);
		}
		else
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		des.init(buf[ISO7816.OFFSET_P1], buf[ISO7816.OFFSET_P2]);
		//****** 3 *******��������/���Ľ���DES���ܲ��õ�����/����
		des.GetResult(buf, (short)ISO7816.OFFSET_CDATA, (short)buf[ISO7816.OFFSET_LC], result, (short)0);
		Util.arrayCopyNonAtomic(result, (short)0, buf, (short)ISO7816.OFFSET_CDATA, (short)buf[ISO7816.OFFSET_LC]);
		apdu.setOutgoingAndSend((short)5, (short)buf[ISO7816.OFFSET_LC]);
	}
	
	private void handleRSA(APDU apdu) throws ISOException
	{
		byte[] buf = apdu.getBuffer();
		apdu.setIncomingAndReceive();//��ȡdata
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
		apdu.setIncomingAndReceive();//��ȡdata
		byte p1 = buf[ISO7816.OFFSET_P1];
		hmac.Init(p1);  //���ȸ���p1������ȷ��Ҫ�õ�����hash�㷨
		hmac.GetResult(buf, (short)ISO7816.OFFSET_CDATA, (short)buf[ISO7816.OFFSET_LC], result, (short)0);
		Util.arrayCopyNonAtomic(result, (short)0, buf, (short)ISO7816.OFFSET_CDATA, (short)64);
		apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)64);
	}
	
	private void handleAES(APDU apdu) throws ISOException
	{
		byte[] buf = apdu.getBuffer();
		apdu.setIncomingAndReceive();//��ȡdata
		byte p1 = buf[ISO7816.OFFSET_P1];
		
		/* �������ֶ�����DES��Կ */
		if(p1 == (byte)0) //������Կ
		{
			aes.setAESKey(buf, (short)5);
			aes.getAESKey(buf, (short)ISO7816.OFFSET_CDATA);
			apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)8);
			return;	//ע��Ҫreturn���ܲ�ִ������Ĵ���
		}
		else if(p1 == (byte)1) //����
		{
			if(!aes.isKeyInitialized()) //δ������Կ
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			byte p2 = buf[ISO7816.OFFSET_P2]; //p2ָ���㷨ģʽ
			if((p2 != (byte)13) && (p2 != (byte)14) && ((p2 < (byte)18) || (p2 > (byte)27)))//p1�ܴ����㷨ģʽ
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			aes.init(p1, p2);
		}
		else if(p1 == (byte)2)	//����
		{
			if(!aes.isKeyInitialized()) //δ������Կ
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			byte p2 = buf[ISO7816.OFFSET_P2];
			if((p2 != (byte)13) && (p2 != (byte)14) && ((p2 < (byte)18) || (p2 > (byte)27)))//p1�ܴ����㷨ģʽ
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			aes.init(p1, p2);
		}
		else
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		aes.init(buf[ISO7816.OFFSET_P1], buf[ISO7816.OFFSET_P2]);
		//****** 3 *******��������/���Ľ���DES���ܲ��õ�����/����
		aes.GetResult(buf, (short)ISO7816.OFFSET_CDATA, (short)buf[ISO7816.OFFSET_LC], result, (short)0);
		Util.arrayCopyNonAtomic(result, (short)0, buf, (short)ISO7816.OFFSET_CDATA, (short)buf[ISO7816.OFFSET_LC]);
		apdu.setOutgoingAndSend((short)5, (short)buf[ISO7816.OFFSET_LC]);
	}
	
	private void handleSIGN(APDU apdu) throws ISOException
	{
		byte[] buf = apdu.getBuffer();
		apdu.setIncomingAndReceive();//��ȡdata
		short signLen = (short)0;
		if(buf[ISO7816.OFFSET_P1] == (byte)0x00) //p1 == 00 ��ʾ��ǩ
		{
			mySign.init(true);
			signLen = mySign.sign(buf, (short)ISO7816.OFFSET_CDATA, (short)buf[ISO7816.OFFSET_LC], result, (short)0);
			Util.arrayCopyNonAtomic(result, (short)0, buf, (short)ISO7816.OFFSET_CDATA, signLen);
			apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, signLen);
		}
		else 	//��ʾ��ǩ
		{
			mySign.init(false);
			//��Ҫapduͬʱ����Message�Լ�ǩ��,������p2�������зֿ�����
			//short temp = (short)(lc - p2); //����������ʱ�۲�ֵ�ı仯
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
		case (byte) 0x00:	//INS == 0x00 ����Ҫ��DES����
			handleDES(apdu);
			break;	//һ��Ҫ��break������������switchѭ��
			
		case (byte) 0x01:	//INS == 0x01 ��ʾҪ��RSA�㷨
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


/**���ļ�ע�����
 * 
 * ע��һ������new�Ķ�Ӧ�þ����ڹ���ʱ��ɣ�����ÿ�η���һ��APDU����������newһ��ռ���������¿ռ��˷�
 * 
 * ע���������/���ܵõ���result���鿪�ٿռ�Ĵ�С(S)����
 * 			DES�Ŀռ�S >= ����/���ĳ���, RSA��S >= ��Կ�ֽ���(512���س��ȵ���ԿΪ64�ֽ�)
 * 
 * ע������switch-case��ÿ��case֮��һ��Ҫ��break������������switchѭ��
 * 
 * ע��������ǩʱ��Ϊ��Ҫͬʱ����ԭʼ��Ϣ�Լ�ǩ��������һ��apdu������Ҫ�����ˡ���Ϣ+ǩ����
 *         ����ע��lc��ֵ����lenOf(Message)+lenOf(sign)��
 *         ͬʱ,Ϊ���зֿ�����������,�Ҷ����õ���p2������
 *         ����Ҫע�����p2��lc��ֵ����ȥ�Ķ���ʮ�����Ʊ��,Applet���յ�apdu֮���������Զ�ת��ʮ���Ʊ�ʾ(debug���ɹ۲쵽),
 *         ����p2������Message�ֽڳ��ȵ�ʮ�����Ʊ��,lc������data���ֵ��ֽڳ��ȵ�ʮ�����Ʊ��,������Ҫ��������ȥת����ʮ������send
 * 
 * ������Ľ�����ʵ����Ŀ����ʱ��Ҫ��Des.java����Щ�����ļ�ȫ�����ɵ���Applet�ļ���        
 * 
 * */
