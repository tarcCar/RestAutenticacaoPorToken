package br.com.projetoRest.services;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Response;

import br.com.projetoRest.model.NivelPermissao;
import br.com.projetoRest.seguranca.Seguro;

@Path("servicos")
public class ConversorMedidasService {

	@Seguro({NivelPermissao.NIVEL_1})
	@GET
	@Path("quilometrosParaMilhas/{quilometros}")
	//Metodo que faz um simples conversão de quilometro para milhas
	public Response quilometroParaMilha(@PathParam("quilometros")Double quilometros){
		quilometros = quilometros / 1.6;
		return Response.ok(quilometros).build();
	}
	
	@Seguro({NivelPermissao.NIVEL_2})
	@GET
	@Path("milhasParaQuilometros/{milhas}")
	//Metodo que faz um simples conversão de milhas para quilometros
	public Response milhasParaQuilometros(@PathParam("milhas")Double milhas){
		milhas = milhas * 1.6;
		return Response.ok(milhas).build();
	}
}
