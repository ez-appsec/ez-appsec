// True negative: DTO with explicit field mapping (safe)
@RestController
public class UserController {

    @Autowired
    private UserRepository userRepo;

    @PostMapping("/users")
    // ok: ez-spring-mass-assignment
    public User createUser(@RequestBody CreateUserDto dto) {
        User user = new User();
        user.setName(dto.getName());
        user.setEmail(dto.getEmail());
        return userRepo.save(user);
    }
}
