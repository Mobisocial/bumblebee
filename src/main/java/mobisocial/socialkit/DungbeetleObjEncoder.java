package mobisocial.socialkit;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import mobisocial.socialkit.musubi.RSACrypto;
import mobisocial.socialkit.util.FastBase64;

import org.apache.commons.io.output.NullOutputStream;
import org.json.JSONException;
import org.json.JSONObject;

import edu.stanford.mobisocial.bumblebee.CryptoException;
import edu.stanford.mobisocial.bumblebee.util.Util;

/**
 * The classic format of a Dungbeetle object.
 * 
 * <p>Features:
 * <ul>
 * <li> RSA user keys
 * <li> 128-bit AES message encryption key
 * <li> AES/CBC/PKCS5Padding message encryption
 *
 */
public class DungbeetleObjEncoder implements ObjEncoder<DungbeetleEncodedObj> {
    private static final int AES_Key_Size = 128;
    private static KeyGenerator mKeyGenerator;
    private final User mLocalUser;

    public DungbeetleObjEncoder(User localUser) {
        mLocalUser = localUser;
    }

    public DungbeetleEncodedObj encodeObj(PreparedObj obj) throws ObjEncodingException {
        byte[] plain = objAsByteArray(obj);
        if (plain == null) {
            throw new ObjEncodingException("Error converting obj to byte array");
        }
        List<RSAPublicKey> toPubKeys = getPublicKeys(obj.getRecipients());
        try {
            byte[] aesKey = makeAESKey();
            SecretKeySpec aesSpec = new SecretKeySpec(aesKey, "AES");

            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bo);

            User sender = obj.getSender();
            String pkString = sender.getAttribute(User.ATTR_RSA_PUBLIC_KEY);
            byte[] userPidBytes = RSACrypto.publicKeyFromString(pkString).getEncoded();
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

                // TODO: Defined by the ObjEncoder.
                // An application that handles an ObjEncoder's EncodedObj must
                // understand how to map these ids.
                String pid = RSACrypto.makePersonIdForPublicKey(pubk);
                byte[] personIdBytes = pid.getBytes("UTF8");
                out.writeShort(personIdBytes.length);
                out.write(personIdBytes);

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
            String pkeyStr = sender.getAttribute(User.ATTR_RSA_PRIVATE_KEY);
            RSAPrivateKey pkey = RSACrypto.privateKeyFromString(pkeyStr);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pkey);
            byte[] sigBytes = cipher.doFinal(digest);

            ByteArrayOutputStream so = new ByteArrayOutputStream();
            DataOutputStream finalOut = new DataOutputStream(so);
            finalOut.writeShort(sigBytes.length);
            finalOut.write(sigBytes);
            bo.writeTo(finalOut);
            bo = null;
            finalOut.close();
            
            byte[] encoded = so.toByteArray();
            finalOut = null;
            so = null;
            return new DungbeetleEncodedObj(encoded);
        } catch (Exception e) {
            throw new ObjEncodingException(e);
        }
    }

    private List<RSAPublicKey> getPublicKeys(List<User> recipients) throws ObjEncodingException {
        List<RSAPublicKey> keys = new ArrayList<RSAPublicKey>(recipients.size());
        for (User r : recipients) {
            String str = r.getAttribute(User.ATTR_RSA_PUBLIC_KEY);
            if (str == null) {
                throw new ObjEncodingException("No key for user " + r.getId());
            }
            keys.add(RSACrypto.publicKeyFromString(str));
        }
        return keys;
    }

    public SignedObj decodeObj(DungbeetleEncodedObj obj) throws ObjEncodingException {
        try {
            // TODO: signature wrapped vs. not
            byte[] s = obj.getEncoding();
            ByteArrayInputStreamWithPos bi = new ByteArrayInputStreamWithPos(s);
            DataInputStream in = new DataInputStream(bi);

            short sigLen = in.readShort();
            byte[] sigIn = new byte[sigLen];
            in.readFully(sigIn);

            // Decrypt digest
            RSAPublicKey sender = obj.getSenderPublicKey();
            Cipher sigcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            sigcipher.init(Cipher.DECRYPT_MODE, sender);
            byte[] sigBytes = sigcipher.doFinal(sigIn);

            MessageDigest sha1 = MessageDigest.getInstance("SHA1");
            sha1.update(s, 2 + sigLen, s.length - (2 + sigLen));
            byte[] digest = sha1.digest();
            boolean status = Arrays.equals(digest, sigBytes);
            if (!status) {
                throw new CryptoException("Failed to verify signature.");
            }

            short fromPidLen = in.readShort();
            in.skipBytes(fromPidLen);

            byte[] userPidBytes = mLocalUser.getId().getBytes();
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
            String pkString = mLocalUser.getAttribute(User.ATTR_RSA_PRIVATE_KEY);
            RSAPrivateKey pkey = RSACrypto.privateKeyFromString(pkString);
            keyCipher.init(Cipher.DECRYPT_MODE, pkey);
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
            return new DungbeetleSignedObj(plainText);
        } catch (Exception e) {
            throw new ObjEncodingException(e.getMessage());
        }
    }

    private byte[] objAsByteArray(PreparedObj obj) {
        JSONObject json = obj.getJson();
        if (json == null) {
            json = new JSONObject();
        }
        try {
            json.put("type", obj.getType());
            json.put("feedName", obj.getFeedName());
            json.put("sequenceId", obj.getSequenceNumber());
            json.put("timestamp", obj.getTimestamp());
            json.put("appId", obj.getAppId());
            if (obj.getInt() != null) {
                json.put("obj_intkey", obj.getInt().intValue());
            }
            if (obj.getRaw() != null) {
                String data = FastBase64.encodeToString(obj.getRaw());
                json.put("data", data);
            }
        } catch (JSONException e) {
            return null;
        }
        return json.toString().getBytes();
    }

    /**
     * Workaround to retrieve protected member.
     */
    private class ByteArrayInputStreamWithPos extends ByteArrayInputStream {
        public ByteArrayInputStreamWithPos(byte[] b) {
            super(b);
        }

        public int getPos() {
            return pos;
        }
    }

    /**
     * Creates a new AES key
     */
    private byte[] makeAESKey() throws NoSuchAlgorithmException {
        if (mKeyGenerator == null) {
            mKeyGenerator = KeyGenerator.getInstance("AES");
            mKeyGenerator.init(AES_Key_Size);
        }
        SecretKey key = mKeyGenerator.generateKey();
        return key.getEncoded();
    }
}

class DungbeetleSignedObj implements SignedObj {
    static final String KEY_TYPE = "type";
    static final String KEY_FEED_NAME = "feedName";
    static final String KEY_SEQUENCE_ID = "sequenceId";
    static final String KEY_TIMESTAMP = "timestamp";
    static final String KEY_APP_ID = "appId";
    static final String KEY_JSON_INT_KEY = "obj_intkey";
    static final String KEY_RAW = "data";

    private final JSONObject mJson;

    public DungbeetleSignedObj(String plainText) throws IllegalArgumentException {
        try {
            mJson = new JSONObject(plainText);
        } catch (JSONException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public String getType() {
        try {
            return mJson.getString(KEY_TYPE);
        } catch (JSONException e) {
            return null;
        }
    }

    public JSONObject getJson() {
        return mJson;
    }

    public byte[] getRaw() {
        if (mJson == null || !mJson.has(KEY_RAW)) {
            return null;
        }
        try {
            return FastBase64.decode(mJson.getString(KEY_RAW));
        } catch (Exception e) {
            return null;
        }
    }

    public Integer getInt() {
        if (mJson.has(KEY_JSON_INT_KEY)) {
            try {
                return mJson.getInt(KEY_JSON_INT_KEY);
            } catch (Exception e) {}
        }
        return null;
    }

    public long getHash() {
        // TODO Auto-generated method stub
        return 0;
    }

    public String getAppId() {
        try {
            return mJson.getString(KEY_APP_ID);
        } catch (JSONException e) {
            return null;
        }
    }

    public User getSender() {
        // TODO Auto-generated method stub
        return null;
    }

    public long getSequenceNumber() {
        try {
            return mJson.getLong(KEY_SEQUENCE_ID);
        } catch (JSONException e) {
            return -1;
        }
    }

    public String getFeedName() {
        try {
            return mJson.getString(KEY_FEED_NAME);
        } catch (JSONException e) {
            return null;
        }
    }
}