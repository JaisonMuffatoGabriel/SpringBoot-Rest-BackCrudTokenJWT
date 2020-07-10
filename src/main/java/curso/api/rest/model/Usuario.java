package curso.api.rest.model;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.ConstraintMode;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.OneToMany;
import javax.persistence.UniqueConstraint;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
public class Usuario implements UserDetails{
	
	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Long id;
	
	private String login;
	
	private String senha;
	
	private String nome;
	
	@OneToMany(mappedBy = "usuario", orphanRemoval = true, cascade = CascadeType.ALL, fetch = FetchType.LAZY)
	private List<Telefone> telefones;
	
	@OneToMany(fetch = FetchType.EAGER) // fetch - carrega tudo o q tem na tabela
	@JoinTable(name = "usuarios_role", //nome da nova tabela
				uniqueConstraints = @UniqueConstraint( //nome nao pode se repetir
						columnNames = {"usuario_id", "role_id"}, // colunas de ond vem os valores
						name="unique_role_user"),//nome da constraint
				joinColumns = @JoinColumn(//unindo a tabela usuario
						name="usuario_id",//coluna da nova tabela q vai receber valor
						referencedColumnName = "id",//coluna de referencia para valor
						table = "usuario",//tabela 1
						unique = false,
						foreignKey = @javax.persistence.ForeignKey(//nova fk
								name="usuario_fk",
								value=ConstraintMode.CONSTRAINT)),
				inverseJoinColumns = @JoinColumn(//tabela 2 de referencia
						name="role_id", //coluna da nova tabela q vai receber novo valor
						referencedColumnName = "id",//coluna de referencia para valor
						table = "role",// tabla 2 q vai fornecer o valor
						unique = false,
						updatable = false,
						foreignKey = @javax.persistence.ForeignKey(
								name="role_fk",
								value=ConstraintMode.CONSTRAINT)))
	private List<Role> roles = new ArrayList<Role>();

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getLogin() {
		return login;
	}

	public void setLogin(String login) {
		this.login = login;
	}

	public String getSenha() {
		return senha;
	}

	public void setSenha(String senha) {
		this.senha = senha;
	}

	public String getNome() {
		return nome;
	}

	public void setNome(String nome) {
		this.nome = nome;
	}
	
	public List<Telefone> getTelefones() {
		return telefones;
	}
	
	public void setTelefones(List<Telefone> telefones) {
		this.telefones = telefones;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((id == null) ? 0 : id.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Usuario other = (Usuario) obj;
		if (id == null) {
			if (other.id != null)
				return false;
		} else if (!id.equals(other.id))
			return false;
		return true;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {

		return roles;
	}
	@JsonIgnore
	@Override
	public String getPassword() {
		return this.senha;
	}
	@JsonIgnore
	@Override
	public String getUsername() {
		return this.login;
	}
	@JsonIgnore
	@Override
	public boolean isAccountNonExpired() {
		return true;
	}
	@JsonIgnore
	@Override
	public boolean isAccountNonLocked() {
		return true;
	}
	@JsonIgnore
	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}
	@JsonIgnore
	@Override
	public boolean isEnabled() {
		return true;
	}
	
	
	
	

}
