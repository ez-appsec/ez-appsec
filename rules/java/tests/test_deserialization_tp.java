// True positive: ObjectInputStream from request
import java.io.ObjectInputStream;
import javax.servlet.http.HttpServletRequest;

public class DataImporter {
    public Object importData(HttpServletRequest req) throws Exception {
        // ruleid: ez-spring-insecure-deserialization
        ObjectInputStream ois = new ObjectInputStream(req.getInputStream());
        return ois.readObject();
    }
}
