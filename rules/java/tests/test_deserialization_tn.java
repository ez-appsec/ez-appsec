// True negative: Jackson JSON deserialization (safe)
import com.fasterxml.jackson.databind.ObjectMapper;
import javax.servlet.http.HttpServletRequest;

public class DataImporter {
    public MyDto importData(HttpServletRequest req) throws Exception {
        // ok: ez-spring-insecure-deserialization
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(req.getInputStream(), MyDto.class);
    }
}
