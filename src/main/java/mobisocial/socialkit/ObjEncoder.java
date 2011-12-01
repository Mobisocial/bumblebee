package mobisocial.socialkit;

public interface ObjEncoder<Encoding extends EncodedObj> {

    /**
     * Synchronously encode an obj.
     */
    public Encoding encodeObj(PreparedObj obj) throws ObjEncodingException;

    /**
     * Synchronously decode an obj.
     */
    public SignedObj decodeObj(Encoding encoded) throws ObjEncodingException;

    /**
     * Returns true if this encoder supports the given encoding. Decoding
     * the message may still throw an exception.
     */
    public boolean supportsEncoding(long encodingVersion);

    /**
     * Returns this encoder's encoding format for the given data.
     */
    public Encoding getEncodedObj(byte[] encoded);
}
