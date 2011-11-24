package edu.stanford.mobisocial.bumblebee;

import java.lang.ref.SoftReference;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import junit.framework.TestCase;
import mobisocial.socialkit.DungbeetleEncodedObj;
import mobisocial.socialkit.DungbeetleObjEncoder;
import mobisocial.socialkit.ObjEncodingException;
import mobisocial.socialkit.PreparedObj;
import mobisocial.socialkit.SignedObj;
import mobisocial.socialkit.User;
import mobisocial.socialkit.musubi.RSACrypto;

import org.json.JSONException;
import org.json.JSONObject;

import edu.stanford.mobisocial.bumblebee.util.Base64;

public class EncoderTest extends TestCase {
    static final String TEST_APP = "junit.test";
    static final String FEED_NAME = UUID.randomUUID().toString();

    public void testDungbeetleEncoder() {
        User sender = new TestUser();
        User recipient = new TestUser();
        DungbeetleObjEncoder objEncoder = new DungbeetleObjEncoder(sender);
        DungbeetleObjEncoder objDecoder = new DungbeetleObjEncoder(recipient);
        PreparedObj prepared = new TestPreparedObj(sender, Collections.singletonList(recipient));

        SignedObj signed = null;
        try {
            DungbeetleEncodedObj encoded = objEncoder.encodeObj(prepared);
            signed = objDecoder.decodeObj(encoded);
        } catch (ObjEncodingException e) {
            e.printStackTrace();
            assertTrue(false);
        }

        assertEquals(prepared.getAppId(), signed.getAppId());
        assertEquals(prepared.getFeedName(), signed.getFeedName());
    }

    class TestPreparedObj implements PreparedObj {
        private final User mSender;
        private final String mFeedName;
        private final List<User> mRecipients;

        public TestPreparedObj(User sender, List<User> recipients) {
            mSender = sender;
            mFeedName = UUID.randomUUID().toString();
            mRecipients = recipients;
        }

        public String getType() {
            return "test";
        }
        
        public byte[] getRaw() {
            return null;
        }
        
        public JSONObject getJson() {
            JSONObject json = new JSONObject();
            try {
                json.put("yea", "man");
            } catch (JSONException e) {}
            return json;
        }
        
        public Integer getInt() {
            return null;
        }
        
        public long getTimestamp() {
            return new Date().getTime();
        }
        
        public long getSequenceNumber() {
            return 5;
        }
        
        public User getSender() {
            return mSender;
        }
        
        public List<User> getRecipients() {
            return mRecipients;
        }
        
        public String getFeedName() {
            return mFeedName;
        }
        
        public String getAppId() {
            return TEST_APP;
        }
    }

    class OutgoingFeedObjectMsg extends OutgoingMsg {
        public OutgoingFeedObjectMsg(List<User> recipients, JSONObject json){
            //mPubKeys = mIdent.publicKeysForContactIds(ids);
            //this obj is not yet encoded
            mBody = json.toString();
        }
    }

    abstract class OutgoingMsg implements OutgoingMessage {
        protected SoftReference<byte[]> mEncoded;
        protected String mBody;
        protected List<RSAPublicKey> mPubKeys;
        protected long mObjectId;
        protected JSONObject mJson;
        protected byte[] mRaw;
        protected boolean mDeleteOnCommit;
        protected OutgoingMsg() {
            mObjectId = 0;
        }
        @Override
        public long getLocalUniqueId() {
            return mObjectId;
        }
        public List<RSAPublicKey> toPublicKeys(){ return mPubKeys; }
        public String contents(){ return mBody; }
        public String toString(){ return "[Message with body: " + mBody + " to " +
                toPublicKeys().size() + " recipient(s) ]"; }
        public void onCommitted() {
        }

        @Override
        public void onEncoded(byte[] encoded) {
        }

        @Override
        public byte[] getEncoded() {
            return null;
        }
    }
}

class TestUser implements User {
    private final KeyPair mKeyPair;
    private final String mId;

    static KeyPair generateKeyPair() {
        try {
            // Generate a 1024-bit Digital Signature Algorithm (RSA) key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            return keyGen.genKeyPair();        
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("Failed to generate key pair! " + e);
        }
    }

    public TestUser() {
        mKeyPair = generateKeyPair();
        mId = RSACrypto.makePersonIdForPublicKey(mKeyPair.getPublic());
    }

    @Override
    public String getId() {
        return mId;
    }

    @Override
    public String getName() {
        return "Test User";
    }

    @Override
    public String getAttribute(String attr) {
        if (ATTR_RSA_PUBLIC_KEY.equals(attr)) {
            return Base64.encodeToString(mKeyPair.getPublic().getEncoded(), false);
        }
        if (ATTR_RSA_PRIVATE_KEY.equals(attr)) {
            return Base64.encodeToString(mKeyPair.getPrivate().getEncoded(), false);
        }
        return null;
    }
}
