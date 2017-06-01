package br.com.projetoRest.seguranca;

import java.io.IOException;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.annotation.Priority;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;

import br.com.projetoRest.model.NivelPermissao;
import br.com.projetoRest.services.LoginService;

import javax.ws.rs.Priorities;
//Defini que a @seguro que vai utilizar essa classe
@Seguro
//Indica que essa classe vai prover a funcionalidade pra @seguro não o contario
@Provider
//E prioridade de execucao, pois podemos ter outras classe filtro
//que devem ser executas em uma ordem expecifica
//Nesse caso vai ser executada depois do FiltroAutenticacao,
//pois a prioridade AUTHENTICATION é maio que o do AUTHORIZATION
@Priority(Priorities.AUTHORIZATION)
public class FiltroAutorizacao implements ContainerRequestFilter {
	//O JAX-RS faz a injeção do ResourceInfoque vai ter os informações
	//do metodo que ta sendo verificado 
	@Context
	private ResourceInfo resourceInfo;
	@Override
	public void filter(ContainerRequestContext requestContext) throws IOException {
		// Pega a classe que contem URL requisitada 
		// E extrai os nivel de permissão dela
		Class<?> classe = resourceInfo.getResourceClass();
		List<NivelPermissao> nivelPermissaoClasse = extrairNivelPermissao(classe);

		// Pega o metodo que contem URL requisitada 
		// E extrai os nivel de permissão dele
		Method metodo = resourceInfo.getResourceMethod();
		List<NivelPermissao> nivelPermisaoMetodo = extrairNivelPermissao(metodo);

		try {
			//Como modificamos o securityContext na hora de validar o token, para podemos pegar
			//O login do usuario, para fazer a verificação se ele tem o nivel de permissao necessario
			//para esse endpoint
			String login = requestContext.getSecurityContext().getUserPrincipal().getName();
			// Verifica se o usuario tem permissão pra executar esse metodo
			// Os niveis de acesso do metodo sobrepoe o da classe
			if (nivelPermisaoMetodo.isEmpty()) {
				checarPermissoes(nivelPermissaoClasse,login);
			} else {
				checarPermissoes(nivelPermisaoMetodo,login);
			}

		} catch (Exception e) {
			//Se caso o usuario não possui permissao é dado um execption, 
			//e retorna um resposta com o status 403 FORBIDDEN 
			requestContext.abortWith(
					Response.status(Response.Status.FORBIDDEN).build());
		}
	}
	//Metodo que extrai os niveis de permissao que foram definidos no @Seguro
	private List<NivelPermissao> extrairNivelPermissao(AnnotatedElement annotatedElement) {
		if (annotatedElement == null) {
			return new ArrayList<NivelPermissao>();
		} else {
			Seguro secured = annotatedElement.getAnnotation(Seguro.class);
			if (secured == null) {
				return new ArrayList<NivelPermissao>();
			} else {
				NivelPermissao[] allowedRoles = secured.value();
				return Arrays.asList(allowedRoles);
			}
		}
	}
	//Verifica se o usuario tem permissao pra executar o metodo, se não for definido nenhum nivel de acesso no @Seguro,
	//Entao todos vao poder executar desde que possuam um token valido
	private void checarPermissoes(List<NivelPermissao> nivelPermissaoPermitidos,String login) throws Exception {
		try {
			if(nivelPermissaoPermitidos.isEmpty())
				return;
			
			boolean temPermissao = false;
			//Busca quais os niveis de acesso o usuario tem.
			NivelPermissao nivelPermissaoUsuario = new LoginService().buscarNivelPermissao(login);
			
			for (NivelPermissao nivelPermissao : nivelPermissaoPermitidos) {
				if(nivelPermissao.equals(nivelPermissaoUsuario))
				{
					temPermissao = true;
					break;
				}
			}
			
			if(!temPermissao)
				throw new Exception("Cliente não possui o nível de permissão para esse método");
			
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}
}


