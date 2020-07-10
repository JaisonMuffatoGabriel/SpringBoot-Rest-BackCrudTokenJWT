package curso.api.rest.security;

import java.io.IOException;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import curso.api.rest.ApplicationContextLoad;
import curso.api.rest.model.Usuario;
import curso.api.rest.repository.UsuarioRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/*Classe que cria o token e que valida o token do usuario para cada sessao
 * esta classe no metodo de validacao (authentication) 
 * depende de uma classe auxiliar (ver ApplicationContextLoad - q busca usuario no DB)*/
@Service
@Component
public class JWTTokenAutenticacaoService {

	// define a validade do token, quanto tempo dura em milesegundos(aqui 2 dias)
	private static final long EXPIRATION_TIME = 172800000;

	// uma senha unica para compor a autenticacao e ajuda na seguranca - pode ser qlr uma
	private static final String SECRET = "Senha ExtremamenteSecreta";

	// Prefixo padrao de token - autorizathion : Bearer
	private static final String TOKEN_PREFIX = "Bearer";

	// Sufixo padrao de token - Autorizathion : Bearer
	private static final String HEADER_STRING = "Authorization";
	
	public void addAuthentication(HttpServletResponse response, String username) throws IOException{
	
		//montagem do token - criando o token novo
		String JWT = Jwts.builder()//chama o gerador de token
						.setSubject(username)// adiciona o usuario no token
						.setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))//pega o o dia e hora atual do sistema e soma com o tempo q defini na var ET para a expiracao do token
						.signWith(SignatureAlgorithm.HS512, SECRET).compact();//hs512 e uma criacao random de senha para o token e adiciona com a var secret e depois compact
		
		//concatena - soma o token gerado com o prefixo
		String token = TOKEN_PREFIX + " " + JWT;// ex: Bearer 5847568734658475 (token random)
		
		//adiciona no cabecalho http
		response.addHeader(HEADER_STRING, token);// ex: Autorizathion : Bearer 657657656787 (exemplo do token completo
		
		//liberando resposta para porta diferente do projeto - angular
		//para o angular -parametro de resposta - para todas as portas, qlqr server
		if(response.getHeader("Access-Control-Allow-Origin") == null) {
		   response.addHeader("Access-Control-Allow-Origin", "*");
			}
		
		
		//excreve o token como resposta no corpo http
		response.getWriter().write("{\"Authorization\": \""+token+"\"}");// formato JSON
		
	}
	
	//retorna o usuario validado com o token ou nao, caso nao seja valido - valida o token para cada requisicao do usuario
	public Authentication getAuthentication(HttpServletRequest request, HttpServletResponse response) {
		
		//pega o token enviado no cabecalho http
		String token = request.getHeader(HEADER_STRING);
		
		if(token != null) {
			//faz a validacao do token do usuario na requisicao
			String user = Jwts.parser().setSigningKey(SECRET)//desmonta - tira o SECRET do token
							.parseClaimsJws(token.replace(TOKEN_PREFIX, ""))// desmonta - tira o Bearer
							.getBody().getSubject();// descobre o usuario ex: jao
			
			if(user !=null) {
				Usuario usuario = ApplicationContextLoad.getaApplicationContext()
									.getBean(UsuarioRepository.class).findUserByLogin(user);
				//busca o usuario no banco atraves da classe auxiliar ApplicationContextLoad
				
					if(usuario != null) {
						return new UsernamePasswordAuthenticationToken(
								usuario.getLogin(),
								usuario.getSenha(),
								usuario.getAuthorities());// autorizacao de ROLE
					}
			}
		}
		
	
		liberacaoCors(response);// libera CORS para outras aplicacoes
		return null; // null se usuario nao e autorizado
		
	}

	private void liberacaoCors(HttpServletResponse response) {
		
		if(response.getHeader("Access-Control-Allow-Origin") == null) {
		   response.addHeader("Access-Control-Allow-Origin", "*");
		}
		
		if(response.getHeader("Access-Control-Allow-Headers") == null) {
		   response.addHeader("Access-Control-Allow-Headers", "*");
		}
		
		if(response.getHeader("Access-Control-Request-Headers") == null) {
		   response.addHeader("Access-Control-Request-Headers", "*");
		}
		
		if(response.getHeader("Access-Control-Allow-Methods") == null) {
		   response.addHeader("Access-Control-Allow-Methods", "*");
		}
	}
	
}
