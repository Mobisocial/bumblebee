package mobisocial.socialkit;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

public class DungbeetleEncodedObj implements EncodedObj {
    private final byte[] mEncoding;

    DungbeetleEncodedObj(byte[] encoding) {
        mEncoding = encoding;
    }

    public long getType() {
        return 0x0; // The classic Dungbeetle format has no encoding marker.
    }

    public byte[] getEncoding() {
        return mEncoding;
    }

    public RSAPublicKey getSenderPublicKey() {
        try {
            DataInputStream in = new DataInputStream(
                    new ByteArrayInputStream(mEncoding));
            short sigLen = in.readShort();
            in.skipBytes(sigLen);
            short fromPidLen = in.readShort();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] dest = new byte[fromPidLen];
            System.arraycopy(mEncoding, 2 + sigLen + 2, dest, 0, fromPidLen);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(dest);
            return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
        } catch (Exception e) {
            return null;
        }
    }
}