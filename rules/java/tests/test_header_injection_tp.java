// True positive: user input in response header
@Controller
public class LanguageController {

    @GetMapping("/set-lang")
    public void setLang(HttpServletRequest req, HttpServletResponse resp) {
        // ruleid: ez-spring-header-injection
        String lang = req.getParameter("lang");
        resp.setHeader("Content-Language", lang);
    }
}
