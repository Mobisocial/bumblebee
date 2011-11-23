package mobisocial.socialkit;

import java.util.List;

public interface ObjEncoder<Encoding extends EncodedObj> {

    /**
     * Synchronously encode an obj.
     */
    public Encoding encodeObj(User from, List<User> to, Obj obj);

    /**
     * Synchronously decode an obj.
     */
    public SignedObj decodeObj(Encoding encoded);
}
