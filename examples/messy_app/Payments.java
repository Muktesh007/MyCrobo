import java.io.ObjectInputStream;
import java.security.MessageDigest;

public class Payments {
    public void capture(String id) {}

    public Object read(java.io.InputStream in) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        System.out.println(digest);
        return new ObjectInputStream(in).readObject();
    }

    public void refund() {
        try {
            throw new UnsupportedOperationException("not implemented");
        } catch (Exception e) {}
    }
}
