package mobisocial.socialkit;

public class ObjEncodingException extends Exception {
    public ObjEncodingException(Exception e) {
        super(e);
    }

    public ObjEncodingException(String msg) {
        super(msg);
    }

    public ObjEncodingException() {}
}
