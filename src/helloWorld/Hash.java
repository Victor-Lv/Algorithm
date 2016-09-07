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
	
	public void Init(byte algorithm) { //直接传p1进来确定用哪种算法
		
		/**或许不支持的算法参数-->getInstance()会导致6F00
		 3:MessageDigest.ALG_RIPEMD160
		 5:MessageDigest.ALG_SHA_384
		 6:MessageDigest.ALG_SHA_512
		 */
		HashEngine = MessageDigest.getInstance(algorithm, false);
		//HashEngine = MessageDigest.getInitializedMessageDigestInstance(MessageDigest.ALG_SHA, false);//同样适用
		
	}
	
	public void GetResult(byte[] inBuf, short inOffset, short inLength, byte[] outBuf, short outOffset)
	{
		//sha-1产生的摘要结果固定为160bit[20bytes]
			//其他sha对应的摘要字节数可查看MessageDigest.ALG_弹出的注释窗口
		HashEngine.doFinal(inBuf, inOffset, inLength, outBuf, outOffset);
	}
}

/*
 * 1.HASH如sha、md5，只是将原文产生一段信息摘要，仅用来验证(只能自验?只能自验有啥用处)消息的完整性也就是检测原文是否被篡改。
 * 		也就是说hash的作用是保证任意一段原文对应唯一的hash值。
 *      并且sha/md5这些都是带密钥的哈希,也就是说不同密钥下同个原文产生的hash又不同!
 *      但是明显攻击者我自己用随便一段消息生成hash值，发出去看到的也是"读的通"的消息且hash正确。
 *      所以做数字签名在hash基础上，还需要验证身份！那就是在hash值之后加上非对称密钥加解密！
 * 
 * 2.sha-1产生的摘要结果固定为160bit[20bytes]，并且即便你输入的原文过短，它也会帮你做padding
 * 
 * 3.奇怪，过了几天再调试发现每次很短的同样Message输入最后得到的Digest也都是固定的了
 */