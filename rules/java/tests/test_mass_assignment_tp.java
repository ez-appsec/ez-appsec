// True positive: entity bound directly from request
@RestController
public class UserController {

    @Autowired
    private UserRepository userRepo;

    @PostMapping("/users")
    // ruleid: ez-spring-mass-assignment
    public User createUser(@ModelAttribute User user) {
        return userRepo.save(user);
    }
}
