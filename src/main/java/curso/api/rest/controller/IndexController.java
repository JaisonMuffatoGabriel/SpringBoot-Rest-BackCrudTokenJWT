package curso.api.rest.controller;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CachePut;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import curso.api.rest.model.Usuario;
import curso.api.rest.repository.UsuarioRepository;

@RestController
@RequestMapping(value="/usuario")
@CrossOrigin(origins = "*")
public class IndexController {
	
	@Autowired
	private UsuarioRepository usuarioRepository;
	
	@GetMapping(value = "/",produces = "application/json")
	@CachePut("cacheusuario")//mantem a cache atualizada com entradas e saidas
	public ResponseEntity<List<Usuario>> BuscaTodos() {
		
		List<Usuario> listaUsuario =usuarioRepository.findAll();
		
		return new ResponseEntity<List<Usuario>>( listaUsuario, HttpStatus.OK);
	}
	
	
	@GetMapping(value="/{id}", produces="application/json")
	@CachePut("cacheusuario")
	public ResponseEntity <Usuario> BuscaId(@PathVariable(value="id") Long id) {
		
		Optional<Usuario> usuario = usuarioRepository.findById(id);
		
		return new ResponseEntity<Usuario>(usuario.get(), HttpStatus.OK);
		
	}
	
	@GetMapping(value="/usuarioPorNome/{nome}", produces = "application/json")
	@CachePut("cacheusuario")
	public ResponseEntity<List<Usuario>> usuarioPorNome(@PathVariable("nome") String nome) throws InterruptedException{
		
		List<Usuario> list = usuarioRepository.findUserByNome(nome);
		
		return new ResponseEntity<List<Usuario>>(list, HttpStatus.OK);
	}
	
	
	
	
	@PostMapping(value="/", produces ="application/json")
	public ResponseEntity<Usuario> salvaUsuario(@RequestBody Usuario usuario){
		
		if(usuario.getTelefones() !=null) {
			for(int pos = 0; pos < usuario.getTelefones().size(); pos++) {
				usuario.getTelefones().get(pos).setUsuario(usuario);
			}
		}
		
		//criptografa a senha
		String senhaCriptografada = new BCryptPasswordEncoder().encode(usuario.getSenha());
		usuario.setSenha(senhaCriptografada);
		
		Usuario usuarioSalvo = usuarioRepository.save(usuario);
		
		return new ResponseEntity<Usuario>(usuarioSalvo, HttpStatus.OK);
	}
	
	@PutMapping(value="/", produces="application/json")
	public ResponseEntity<Usuario> Update(@RequestBody Usuario usuario){
		
		for(int pos = 0; pos < usuario.getTelefones().size(); pos++) {
			usuario.getTelefones().get(pos).setUsuario(usuario);
		}
		
		Usuario userTemporario = usuarioRepository.findById(usuario.getId()).get();
		
		if(!userTemporario.getSenha().equals(usuario.getSenha())) {
			String senhaCriptografada = new BCryptPasswordEncoder().encode(usuario.getSenha());
			usuario.setSenha(senhaCriptografada);
		}
		
		Usuario usuarioUpdate =usuarioRepository.save(usuario);
		
		return new ResponseEntity<Usuario>(usuarioUpdate, HttpStatus.OK);
		
	}
	@DeleteMapping(value="/{id}", produces="application/text")
	public String Delete(@PathVariable(value="id") Long id) {
		
		usuarioRepository.deleteById(id);
		
		return "Usuario deletado";
	}
}
