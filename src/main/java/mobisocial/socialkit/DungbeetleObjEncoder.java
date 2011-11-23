package mobisocial.socialkit;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.output.NullOutputStream;

/**
 * The classic format of a Dungbeetle object.
 * 
 * <p>Features:
 * <ul>
 * <li> RSA user keys
 * <li> Per-recipient key encryption
 * <li> 128-bit AES message encryption
 *
 */
public class DungbeetleObjEncoder implements ObjEncoder<DungbeetleEncodedObj> {
    public long PROTOCOL = 1;
    public DungbeetleEncodedObj encodeObj(User sender, List<User> to, Obj obj) {
        byte[] plain = objAsByteArray(obj);
        List<RSAPublicKey> toPubKeys = m.toPublicKeys();
        try {
            byte[] aesKey = makeAESKey();
            SecretKeySpec aesSpec = new SecretKeySpec(aesKey, "AES");

            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bo);

            byte[] userPidBytes = sender.getPublicKey().getEncoded();
            out.writeShort(userPidBytes.length);
            out.write(userPidBytes);

            out.writeShort(toPubKeys.size());

            // Encrypt the AES key with each key in toPubKeys
            for (RSAPublicKey pubk : toPubKeys) {
                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.ENCRYPT_MODE, pubk);
                ByteArrayOutputStream ks = new ByteArrayOutputStream();
                CipherOutputStream os = new CipherOutputStream(ks, cipher);
                os.write(aesKey);
                os.close();
                byte[] aesKeyCipherBytes = ks.toByteArray();

                String pid = mIdent.personIdForPublicKey(pubk);
                byte[] toPersonIdBytes = pid.getBytes("UTF8");
                out.writeShort(toPersonIdBytes.length);
                out.write(toPersonIdBytes);

                out.writeShort(aesKeyCipherBytes.length);
                out.write(aesKeyCipherBytes);
            }

            // Generate Initialization Vector for AES CBC mode
            SecureRandom random = new SecureRandom();
            byte[] iv = new byte[16];
            random.nextBytes(iv);
            out.writeShort(iv.length);
            out.write(iv);

            // Use AES key to encrypt the body
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, aesSpec, ivspec);
            ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
            CipherOutputStream aesOut = new CipherOutputStream(cipherOut,
                    aesCipher);
            aesOut.write(plain);
            plain = null;
            aesOut.close();
            aesOut = null;
            out.writeInt(cipherOut.size());
            cipherOut.writeTo(out);
            cipherOut = null;
            out.close();
            bo.close();

            MessageDigest sha1 = MessageDigest.getInstance("SHA1");
            DigestOutputStream dos = new DigestOutputStream(new NullOutputStream(), sha1);
            bo.writeTo(dos);
            dos.flush();
            byte[] digest = sha1.digest();
            // Encrypt digest
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, mIdent.userPrivateKey());
            byte[] sigBytes = cipher.doFinal(digest);

            ByteArrayOutputStream so = new ByteArrayOutputStream();
            DataOutputStream finalOut = new DataOutputStream(so);
            finalOut.writeShort(sigBytes.length);
            finalOut.write(sigBytes);
            bo.writeTo(finalOut);
            bo = null;
            finalOut.close();
            
            encoded = so.toByteArray(); 
            finalOut = null;
            so = null;
            m.onEncoded(encoded);
            return encoded;
    }

    public SignedObj decodeObj(DungbeetleEncodedObj obj) {
        return null;
    }
}

/**
 * TODO: Re-implement the current encoding format.
 *
 */
class DungbeetleEncodedObj extends MemEncodedObj {

    public DungbeetleEncodedObj(Obj obj) {
        obj.getJson();
    }

    public String getEncodingType() {
        return "IDENTITY";
    }

    public byte[] getEncodedObj() {
        // TODO Auto-generated method stub
        return null;
    }

    public byte[] getSignature() {
        // TODO Auto-generated method stub
        return null;
    }

    public User getSender() {
        // TODO Auto-generated method stub
        return null;
    }

    public List<User> getRecipients() {
        // TODO Auto-generated method stub
        return null;
    }

}
