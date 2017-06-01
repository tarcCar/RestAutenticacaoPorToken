package br.com.projetoRest.seguranca;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import javax.ws.rs.NameBinding;

import br.com.projetoRest.model.NivelPermissao;


@NameBinding
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE,ElementType.METHOD})
public @interface Seguro { 
	NivelPermissao[] value() default{};
}

