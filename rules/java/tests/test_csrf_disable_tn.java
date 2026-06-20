// True negative: CSRF enabled (default, safe)
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    // ok: ez-spring-csrf-disable
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .anyRequest().authenticated()
            .and()
            .formLogin();
    }
}
