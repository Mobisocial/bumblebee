package edu.stanford.mobisocial.bumblebee;

import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

import mobisocial.socialkit.DungbeetleObjEncoder;
import mobisocial.socialkit.EncodedObj;
import mobisocial.socialkit.ObjEncodingException;
import mobisocial.socialkit.SignedObj;

public class MessageFormat {

	private TransportIdentityProvider mIdent;
	private DungbeetleObjEncoder mDungbeetleEncoder;

	public MessageFormat(TransportIdentityProvider ident) {
		mIdent = ident;
		mDungbeetleEncoder = new DungbeetleObjEncoder(mIdent);
	}

	public SignedObj decodeIncomingMessage(byte[] received) throws ObjEncodingException {
	    ByteBuffer buf = ByteBuffer.wrap(received);
        long encodingFormat = buf.getLong();
        if (mDungbeetleEncoder.supportsEncoding(encodingFormat)) {
            return mDungbeetleEncoder.decodeObj(mDungbeetleEncoder.getEncodedObj(received));
        }
        throw new ObjEncodingException("No suitable encoder found for " + encodingFormat);
	}

	public EncodedObj encodeOutgoingMessage(OutgoingMessage m)
			throws CryptoException {
		EncodedObj encoded = m.getEncoded();
		if(encoded != null) {
			return encoded;
		}
		try {
    		EncodedObj enc = mDungbeetleEncoder.encodeObj(m.contents());
    		m.onEncoded(enc);
    		return enc;
		} catch (Exception e) {
			e.printStackTrace(System.err);
			throw new CryptoException(e);
		}
	}
}
