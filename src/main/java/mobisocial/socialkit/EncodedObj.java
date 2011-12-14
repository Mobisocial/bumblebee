package mobisocial.socialkit;

public interface EncodedObj {
    public long getEncodingType();
    public byte[] getEncoded();
    public byte[] getSignature();
}
