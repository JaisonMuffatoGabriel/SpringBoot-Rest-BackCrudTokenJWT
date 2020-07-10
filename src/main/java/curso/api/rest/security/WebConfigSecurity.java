package curso.api.rest.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import curso.api.rest.service.ImplementacaoUserDetailsService;

@Configuration
@EnableWebSecurity
public class WebConfigSecurity  extends WebSecurityConfigurerAdapter{
	
	@Autowired
	private ImplementacaoUserDetailsService implementacaoUserDetailsService;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception{
		
		//ativa a protecao contra usuario q nao esta validado no sistema
		http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
		
		//ativa a permissao para acesso a pagina inicial EX: sistema.com/index
		.disable().authorizeRequests().antMatchers("/").permitAll()
		.antMatchers("/index").permitAll()
		
		.antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
		
		//url de logout - redireciona apos deslogar
		.anyRequest().authenticated().and().logout().logoutSuccessUrl("/index")
		
		//mapeia url de logout e invalida  o usuario
		.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
		
		//filtra requisicao de login para autenticacao
		.and().addFilterBefore(new JWTLoginFilter("/login", authenticationManager()), 
				UsernamePasswordAuthenticationFilter.class)
		
		//filtra demais requisicoes para verificacao do token jwt no header http
		.addFilterBefore(new JWTApiAutenticacaoFilter(), UsernamePasswordAuthenticationFilter.class);
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception{
		
		//service que ira consultar o usuario no banco de dados
		auth.userDetailsService(implementacaoUserDetailsService)
		
		//padrao de digitacao de senha
		.passwordEncoder(new BCryptPasswordEncoder());
	}

}
