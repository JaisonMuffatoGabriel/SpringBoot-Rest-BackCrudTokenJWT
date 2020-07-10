package curso.api.rest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@SpringBootApplication //original
@EntityScan(basePackages = {"curso.api.rest.model"})//faz scan nos pacotes p/ adm entidades
@ComponentScan(basePackages = {"curso.*"})// scan pacotes p/ injecao de dependencia
@EnableJpaRepositories(basePackages = {"curso.api.rest.repository"})//abilita interface de repositorio
@EnableTransactionManagement// gerencia as transacoes com o banco evitando problemas
@EnableWebMvc //abilita mvc
@RestController //abilita rest
@EnableAutoConfiguration// gerencia configuracoes do projeto
@EnableCaching //ativa o servico de cache - adiciono @cacheable no metodo q interessa cache -ex-list
public class CursospringrestapiApplication implements WebMvcConfigurer {

	public static void main(String[] args) {
		SpringApplication.run(CursospringrestapiApplication.class, args);
		System.out.println(new BCryptPasswordEncoder().encode("123"));
	}
	
	//mapeamento Global que refletem em todo sistema - CORS
	@Override
	public void addCorsMappings(CorsRegistry registry) {
		registry.addMapping("/usuario/**")
		.allowedMethods("*")
		.allowedOrigins("*");
		//libera o mapeamento de usuario para todas as origens
		
	}

}
