package edu.stanford.mobisocial.bumblebee;

import edu.stanford.mobisocial.bumblebee.util.*;
import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import mobisocial.socialkit.DungbeetleObjEncoder;
import mobisocial.socialkit.EncodedObj;
import mobisocial.socialkit.ObjEncoder;

import org.apache.commons.io.output.NullOutputStream;

public class MessageFormat {

	public static final int AES_Key_Size = 128;
	public static final int SHORT_LEN = 2;
	private TransportIdentityProvider mIdent;

	public MessageFormat(TransportIdentityProvider ident) {
		mIdent = ident;
	}

	public String getMessagePersonId(byte[] s) {
		try {
			RSAPublicKey k = getMessagePublicKey(s);
			if (k == null)
				return null;
			return mIdent.personIdForPublicKey(k);
		} catch (Exception e) {
			e.printStackTrace(System.err);
			return null;
		}
	}

	public RSAPublicKey getMessagePublicKey(byte[] s) {
		try {
			DataInputStream in = new DataInputStream(
					new ByteArrayInputStream(s));
			short sigLen = in.readShort();
			in.skipBytes(sigLen);
			short fromPidLen = in.readShort();
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			byte[] dest = new byte[fromPidLen];
			System.arraycopy(s, SHORT_LEN + sigLen + SHORT_LEN, dest, 0,
					fromPidLen);
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(dest);
			return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
		} catch (Exception e) {
			e.printStackTrace(System.err);
			return null;
		}
	}

	private static class ByteArrayInputStreamWithPos extends ByteArrayInputStream {
		public ByteArrayInputStreamWithPos(byte[] b) {
			super(b);
		}

		public int getPos() {
			return pos;
		}
	}

	public String decodeIncomingMessage(byte[] s) throws CryptoException {
		try {
			ByteArrayInputStreamWithPos bi = new ByteArrayInputStreamWithPos(s);
			DataInputStream in = new DataInputStream(bi);

			short sigLen = in.readShort();
			byte[] sigIn = new byte[sigLen];
			in.readFully(sigIn);

			// Decrypt digest
			RSAPublicKey sender = getMessagePublicKey(s);
			Cipher sigcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			sigcipher.init(Cipher.DECRYPT_MODE, sender);
			byte[] sigBytes = sigcipher.doFinal(sigIn);

			MessageDigest sha1 = MessageDigest.getInstance("SHA1");
			sha1.update(s, SHORT_LEN + sigLen, s.length - (SHORT_LEN + sigLen));
			byte[] digest = sha1.digest();
			boolean status = Arrays.equals(digest, sigBytes);
			if (!status) {
				throw new CryptoException("Failed to verify signature.");
			}

			short fromPidLen = in.readShort();
			in.skipBytes(fromPidLen);

			byte[] userPidBytes = mIdent.userPersonId().getBytes("UTF8");

			short numKeys = in.readShort();
			byte[] keyBytesE = null;
			for (int i = 0; i < numKeys; i++) {
				short idLen = in.readShort();
				if (keyBytesE != null) {
					in.skipBytes(idLen);
					short keyLen = in.readShort();
					in.skipBytes(keyLen);
				} else {
					if (Util.bytesEqual(s, bi.getPos(), userPidBytes, 0, idLen)) {
						in.skipBytes(idLen);
						short keyLen = in.readShort();
						keyBytesE = new byte[keyLen];
						in.readFully(keyBytesE);
					} else {
						in.skipBytes(idLen);
						short keyLen = in.readShort();
						in.skipBytes(keyLen);
					}
				}
			}

			if (keyBytesE == null) {
				throw new CryptoException("No key in message for this user!");
			}

			// Decrypt AES key
			Cipher keyCipher = Cipher.getInstance("RSA");
			keyCipher.init(Cipher.DECRYPT_MODE, mIdent.userPrivateKey());
			CipherInputStream is = new CipherInputStream(
					new ByteArrayInputStream(keyBytesE), keyCipher);
			byte[] aesKey = new byte[AES_Key_Size / 8];
			is.read(aesKey);
			is.close();

			short ivLen = in.readShort();
			byte[] ivBytes = new byte[ivLen];
			in.readFully(ivBytes);

			int dataLen = in.readInt();
			// Note the rest of the bytes are the body.
			// We'll just pipe them into the decrypt stream...

			// Use AES key to decrypt the body
			SecretKeySpec aeskeySpec = new SecretKeySpec(aesKey, "AES");
			IvParameterSpec ivspec = new IvParameterSpec(ivBytes);
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, aeskeySpec, ivspec);
			is = new CipherInputStream(in, cipher);
			ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
			Util.copy(is, plainOut);
			is.close();

			byte[] plainBytes = plainOut.toByteArray();
			String plainText = new String(plainBytes, "UTF8");
			return plainText;

		} catch (Exception e) {
			e.printStackTrace(System.err);
			throw new CryptoException(e.getMessage());
		}
	}

	public byte[] encodeOutgoingMessage(OutgoingMessage m)
			throws CryptoException {
		byte[] encoded = m.getEncoded();
		if(encoded != null)
			return encoded;
		ObjEncoder<?> encoder = new DungbeetleObjEncoder(mIdent, null);
		try {
    		EncodedObj enc = encoder.encodeObj(m.contents());
    		m.onEncoded(enc.getEncoding());
    		return enc.getEncoding();
		} catch (Exception e) {
			e.printStackTrace(System.err);
			throw new CryptoException(e);
		}
	}

	/**
	 * Creates a new AES key
	 */
	private byte[] makeAESKey() throws NoSuchAlgorithmException {
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(AES_Key_Size);
		SecretKey key = kgen.generateKey();
		return key.getEncoded();
	}

	public static byte[] getMessageSignature(byte[] body) throws CryptoException {
		ByteArrayInputStreamWithPos bi = new ByteArrayInputStreamWithPos(body);
		DataInputStream in = new DataInputStream(bi);

		try {
			short sigLen = in.readShort();
			byte[] signature = new byte[sigLen];
			in.readFully(signature);
			return signature;
		} catch (Exception e) {
			e.printStackTrace(System.err);
			throw new CryptoException();
		}
	}

	public static long extractHash(byte[] body) throws CryptoException {
		ByteArrayInputStreamWithPos bi = new ByteArrayInputStreamWithPos(body);
		DataInputStream in = new DataInputStream(bi);

		try {
			short sigLen = in.readShort();
			long hash;
			return in.readLong();
		} catch (Exception e) {
			e.printStackTrace(System.err);
			throw new CryptoException();
		}
	}
}
