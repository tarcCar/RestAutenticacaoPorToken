package br.com.projetoRest.seguranca;

import java.io.IOException;
import java.security.Principal;

import javax.annotation.Priority;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.ext.Provider;

import br.com.projetoRest.services.LoginService;
import io.jsonwebtoken.Claims;
//Defini que a @seguro que vai utilizar essa classe
@Seguro
//Indica que essa classe vai prover a funcionalidade pra @seguro não o contario
@Provider
//E prioridade de execucao, pois podemos ter outras classe filtro
//que devem ser executas em uma ordem expecifica
@Priority(Priorities.AUTHENTICATION)
public class FiltroAutenticacao implements ContainerRequestFilter{

	//Aqui fazemos o override do metodo filter  que tem como parametro
	// o ContainerRequestContext que é o objeto que podemos manipular a request
	@Override
	public void filter(ContainerRequestContext requestContext) throws IOException {
		
		//Verifica se o header AUTHORIZATION exite ou não se exite extrai o token 
		//se não abaorta a requsição retornando uma NotAuthorizedException
		String authorizationHeader = requestContext.getHeaderString(HttpHeaders.AUTHORIZATION);
		if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
			throw new NotAuthorizedException("Authorization header precisa ser provido");
		}
		//extrai o token do header
		String token = authorizationHeader.substring("Bearer".length()).trim();
		//verificamos se o metodo é valido ou não
		//se não for valido  a requisição é abortada e retorna uma resposta com status 401 UNAUTHORIZED
		//se for valida modificamos o o SecurityContext da request 
		//para que quando usarmos o  getUserPrincipal retorne o login do usuario 
		try {
			// metodo que verifica  se o token é valido ou não 
			Claims claims = new LoginService().validaToken(token);
			//Caso não for valido vai retornar um objeto nulo e executar um exception
			if(claims==null)
				throw new Exception("Token inválido");
			//Metodo que modifica o SecurityContext pra disponibilizar o login do usuario
			modificarRequestContext(requestContext,claims.getId());
		} catch (Exception e) {
			e.printStackTrace();
			//Caso o token for invalido a requisição é abortada e retorna uma resposta com status 401 UNAUTHORIZED
			requestContext.abortWith(
					Response.status(Response.Status.UNAUTHORIZED).build());
		}
	}
	//Metodo que modfica o SecurityContext
	private void modificarRequestContext(ContainerRequestContext requestContext,String login){
		final SecurityContext currentSecurityContext = requestContext.getSecurityContext();
		requestContext.setSecurityContext(new SecurityContext() {

		    @Override
		    public Principal getUserPrincipal() {

		        return new Principal() {

		            @Override
		            public String getName() {
		                return login;
		            }
		        };
		    }

		    @Override
		    public boolean isUserInRole(String role) {
		        return true;
		    }

		    @Override
		    public boolean isSecure() {
		        return currentSecurityContext.isSecure();
		    }

		    @Override
		    public String getAuthenticationScheme() {
		        return "Bearer";
		    }
		});
	}

}
