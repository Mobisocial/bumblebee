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
}
