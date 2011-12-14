package mobisocial.socialkit;

import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

public final class DungbeetleEncodedObj implements EncodedObj {
    private final byte[] mEncoding;

    DungbeetleEncodedObj(byte[] encoding) {
        mEncoding = encoding;
    }

    public long getEncodingType() {
        return 0x0; // The classic Dungbeetle format has no encoding marker.
    }

    public byte[] getEncoded() {
        return mEncoding;
    }

    public RSAPublicKey getSenderPublicKey() {
        try {
            ByteBuffer in = ByteBuffer.wrap(mEncoding);
            short sigLen = in.getShort();
            in.position(in.position() + sigLen);
            short fromPidLen = in.getShort();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] dest = new byte[fromPidLen];
            System.arraycopy(mEncoding, 2 + sigLen + 2, dest, 0, fromPidLen);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(dest);
            return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
        } catch (Exception e) {
            return null;
        }
    }

    public byte[] getSignature() {
        ByteBuffer buf = ByteBuffer.wrap(mEncoding);
        short sigLen = buf.getShort(2);
        byte[] bytes = new byte[8];
        buf.get(bytes, 0, sigLen);
        return bytes;
    }

    public long getHash() {
        ByteBuffer buf = ByteBuffer.wrap(mEncoding);
        buf.position(2);
        return buf.getLong();
    }
}