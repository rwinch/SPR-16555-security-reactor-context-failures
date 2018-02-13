/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sample;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.reactive.result.view.CsrfRequestDataValueProcessor;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.result.view.AbstractView;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.web.reactive.function.client.ExchangeFilterFunctions.Credentials.basicAuthenticationCredentials;
import static org.springframework.web.reactive.function.client.ExchangeFilterFunctions.basicAuthentication;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(SpringRunner.class)
@ContextConfiguration
public class EnableWebFluxSecurityTests {

	@Autowired
	WebFilterChainProxy springSecurityFilterChain;
	@Autowired
	ConfigurableApplicationContext context;

	@Test
	public void defaultRequiresAuthentication() {

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(this.springSecurityFilterChain)
			.build();

		client.get()
			.uri("/")
			.exchange()
			.expectStatus().isUnauthorized()
			.expectBody().isEmpty();
	}

	// gh-4831
	@Test
	public void defaultMediaAllThenUnAuthorized() {

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(this.springSecurityFilterChain)
			.build();

		client.get()
			.uri("/")
			.accept(MediaType.ALL)
			.exchange()
			.expectStatus().isUnauthorized()
			.expectBody().isEmpty();
	}

	@Test
	public void authenticateWhenBasicThenNoSession() {

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(this.springSecurityFilterChain)
			.filter(basicAuthentication())
			.build();

		FluxExchangeResult<String> result = client.get()
			.attributes(basicAuthenticationCredentials("user", "password"))
			.exchange()
			.expectStatus()
			.isOk()
			.returnResult(String.class);
		result.assertWithDiagnostics(() -> assertThat(result.getResponseCookies().isEmpty()));
	}

	@Test
	public void defaultPopulatesReactorContext() {
		Authentication currentPrincipal = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		WebSessionServerSecurityContextRepository contextRepository = new WebSessionServerSecurityContextRepository();
		SecurityContext context = new SecurityContextImpl(currentPrincipal);
		WebTestClient client = WebTestClientBuilder.bindToWebFilters(
			(exchange, chain) -> contextRepository.save(exchange, context)
				.switchIfEmpty(chain.filter(exchange))
				.flatMap(e -> chain.filter(exchange)),
			this.springSecurityFilterChain,
			(exchange, chain) ->
				ReactiveSecurityContextHolder.getContext()
					.map(SecurityContext::getAuthentication)
					.flatMap( principal -> exchange.getResponse()
						.writeWith(Mono.just(toDataBuffer(principal.getName()))))
		).build();

		client
			.get()
			.uri("/")
			.exchange()
			.expectStatus().isOk()
			.expectBody(String.class).consumeWith( result -> assertThat(result.getResponseBody()).isEqualTo(currentPrincipal.getName()));
	}

	@Test
	public void defaultPopulatesReactorContextWhenAuthenticating() {
		WebTestClient client = WebTestClientBuilder.bindToWebFilters(
			this.springSecurityFilterChain,
			(exchange, chain) ->
				ReactiveSecurityContextHolder.getContext()
					.map(SecurityContext::getAuthentication)
					.flatMap( principal -> exchange.getResponse()
						.writeWith(Mono.just(toDataBuffer(principal.getName()))))
		)
		.filter(basicAuthentication())
		.build();

		client
			.get()
			.uri("/")
			.attributes(basicAuthenticationCredentials("user", "password"))
			.exchange()
			.expectStatus().isOk()
			.expectBody(String.class).consumeWith( result -> assertThat(result.getResponseBody()).isEqualTo("user"));
	}

	@Test
	public void requestDataValueProcessor() {
		CsrfRequestDataValueProcessor rdvp = context.getBean(AbstractView.REQUEST_DATA_VALUE_PROCESSOR_BEAN_NAME, CsrfRequestDataValueProcessor.class);
		assertThat(rdvp).isNotNull();
	}

	@EnableWebFluxSecurity
	@Import(ReactiveAuthenticationTestConfiguration.class)
	static class Config {
	}

	private static DataBuffer toDataBuffer(String body) {
		DataBuffer buffer = new DefaultDataBufferFactory().allocateBuffer();
		buffer.write(body.getBytes(StandardCharsets.UTF_8));
		return buffer;
	}
}
