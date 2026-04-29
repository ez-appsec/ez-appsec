// True positive: CSRF protection explicitly disabled
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // ruleid: ez-spring-csrf-disable
        http.csrf().disable()
            .authorizeRequests()
            .anyRequest().authenticated();
    }
}
