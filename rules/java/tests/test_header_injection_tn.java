// True negative: hardcoded header value (safe)
@Controller
public class LanguageController {

    @GetMapping("/set-lang")
    // ok: ez-spring-header-injection
    public void setLang(HttpServletResponse resp) {
        resp.setHeader("Content-Language", "en-US");
    }
}
