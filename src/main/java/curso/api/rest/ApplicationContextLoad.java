package curso.api.rest;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

/* classe auxiliar para buscar o usuario no banco atraves do usuariorepository e
 * atraves dessa classe aq a classe JWTtokenAutenticacao no metodo authentication
 * que vai validar o token nas requisicoes do usuario
*/
@Component
public class ApplicationContextLoad  implements ApplicationContextAware{
	
	@Autowired
	private static ApplicationContext applicationContext;

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		
		this.applicationContext = applicationContext;
	}
	
	public static ApplicationContext getaApplicationContext() {
		return applicationContext;
	}
	
	

}
