/**
 * Signarure
 * 
 */
package helloWorld;

/**
 * @author lv.lang
 *
 */

import javacard.security.Signature;

public class Sign {
	private Signature signEngine;
	//private Key myKey;
	//private RandGenerator rand;
	//private byte[]temp;
	private Rsa rsa;
	
	public Sign() {
		rsa = new Rsa();
		
		//算法模式参数选用不适会导致6A80,为啥？   //ALG_RSA_MD5_PKCS1模式决定了最后生成的签名长度=RSA密钥长度(如64字节)
		signEngine = Signature.getInstance(Signature.ALG_RSA_MD5_PKCS1, false);
		//myKey = KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, KeyBuilder.LENGTH_HMAC_SHA_1_BLOCK_64, false);
		//temp = JCSystem.makeTransientByteArray((short)64, JCSystem.CLEAR_ON_DESELECT);
		//rand = new RandGenerator();
		//temp = rand.GenrateSecureRand((short)100);
		//((HMACKey)myKey).setKey(temp, (short)0, (short)64);
		
	}
	
	public void init(boolean isSign)
	{
		if(isSign)
			signEngine.init(rsa.GetPrivateKey(), Signature.MODE_SIGN);
			//signEngine.init(myKey, Signature.MODE_SIGN);
		else
			signEngine.init(rsa.GetPublicKey(), Signature.MODE_VERIFY);
			//signEngine.init(myKey, Signature.MODE_VERIFY);
	}
	
	//做签
	public short sign(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset)
	{
		return signEngine.sign(inBuff, inOffset, inLength, sigBuff, sigOffset);
	}
	
	//验签
	public boolean verify(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset, short sigLength)
	{
		return signEngine.verify(inBuff, inOffset, inLength, sigBuff, sigOffset, sigLength);
	}
}
