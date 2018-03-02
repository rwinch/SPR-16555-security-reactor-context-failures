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
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Scope;
import org.springframework.core.ReactiveAdapterRegistry;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.reactive.result.method.annotation.AuthenticationPrincipalArgumentResolver;
import org.springframework.security.web.reactive.result.view.CsrfRequestDataValueProcessor;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.ObjectUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.config.WebFluxConfigurer;
import org.springframework.web.reactive.result.method.annotation.ArgumentResolverConfigurer;
import org.springframework.web.reactive.result.view.AbstractView;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.config.web.server.ServerHttpSecurity.http;
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

	// gh-4831
	@Test
	public void defaultMediaAllThenUnAuthorized() {

		WebTestClient client = WebTestClient
			.bindToController(new Http200RestController())
			.webFilter(this.springSecurityFilterChain)
			.build();

		client.get()
			.uri("/")
			.accept(MediaType.ALL)
			.exchange()
			.expectStatus().isUnauthorized()
			.expectBody().isEmpty();
	}

	@Test
	public void defaultPopulatesReactorContextWhenAuthenticating() {
		WebTestClient client = WebTestClient
				.bindToController(new Http200RestController())
				.webFilter(this.springSecurityFilterChain,
			(exchange, chain) ->
				ReactiveSecurityContextHolder.getContext()
					.map(SecurityContext::getAuthentication)
					.flatMap( principal -> exchange.getResponse()
						.writeWith(Mono.just(toDataBuffer(principal.getName()))))
		)
		.configureClient()
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

	@Configuration
	@Import(ReactiveAuthenticationTestConfiguration.class)
	static class Config implements WebFluxConfigurer {

		public static final int WEB_FILTER_CHAIN_FILTER_ORDER = 0 - 100;

		private static final String BEAN_NAME_PREFIX = "org.springframework.security.config.annotation.web.reactive.WebFluxSecurityConfiguration.";

		private static final String SPRING_SECURITY_WEBFILTERCHAINFILTER_BEAN_NAME = BEAN_NAME_PREFIX + "WebFilterChainFilter";

		@Autowired(required = false)
		private List<SecurityWebFilterChain> securityWebFilterChains;

		@Autowired
		ApplicationContext context;

		@Bean(SPRING_SECURITY_WEBFILTERCHAINFILTER_BEAN_NAME)
		@Order(value = WEB_FILTER_CHAIN_FILTER_ORDER)
		public WebFilterChainProxy springSecurityWebFilterChainFilter() {
			return new WebFilterChainProxy(getSecurityWebFilterChains());
		}

		@Bean(name = AbstractView.REQUEST_DATA_VALUE_PROCESSOR_BEAN_NAME)
		public CsrfRequestDataValueProcessor requestDataValueProcessor() {
			return new CsrfRequestDataValueProcessor();
		}

		private List<SecurityWebFilterChain> getSecurityWebFilterChains() {
			List<SecurityWebFilterChain> result = this.securityWebFilterChains;
			if(ObjectUtils.isEmpty(result)) {
				return Arrays.asList(springSecurityFilterChain());
			}
			return result;
		}

		private SecurityWebFilterChain springSecurityFilterChain() {
			ServerHttpSecurity http = this.context.getBean(ServerHttpSecurity.class);
			return springSecurityFilterChain(http);
		}

		/**
		 * The default {@link ServerHttpSecurity} configuration.
		 * @param http
		 * @return
		 */
		private SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
			http
					.authorizeExchange()
					.anyExchange().authenticated()
					.and()
					.httpBasic().and()
					.formLogin();
			return http.build();
		}

		// --------------------

		private static final String CONFIG_BEAN_NAME_PREFIX = "org.springframework.security.config.annotation.web.reactive.HttpSecurityConfiguration.";
		private static final String HTTPSECURITY_BEAN_NAME = CONFIG_BEAN_NAME_PREFIX + "httpSecurity";

		@Autowired(required = false)
		private ReactiveAdapterRegistry adapterRegistry = new ReactiveAdapterRegistry();

		@Autowired(required = false)
		private ReactiveAuthenticationManager authenticationManager;

		@Autowired(required = false)
		private ReactiveUserDetailsService reactiveUserDetailsService;

		@Autowired(required = false)
		private PasswordEncoder passwordEncoder;

		@Override
		public void configureArgumentResolvers(ArgumentResolverConfigurer configurer) {
			configurer.addCustomResolver(authenticationPrincipalArgumentResolver());
		}

		@Bean
		public AuthenticationPrincipalArgumentResolver authenticationPrincipalArgumentResolver() {
			return new AuthenticationPrincipalArgumentResolver(this.adapterRegistry);
		}

		@Bean(HTTPSECURITY_BEAN_NAME)
		@Scope("prototype")
		public ServerHttpSecurity httpSecurity() {
			return http()
					.authenticationManager(authenticationManager())
					.headers().and()
					.logout().and();
		}

		private ReactiveAuthenticationManager authenticationManager() {
			if(this.authenticationManager != null) {
				return this.authenticationManager;
			}
			if(this.reactiveUserDetailsService != null) {
				UserDetailsRepositoryReactiveAuthenticationManager manager =
						new UserDetailsRepositoryReactiveAuthenticationManager(this.reactiveUserDetailsService);
				if(this.passwordEncoder != null) {
					manager.setPasswordEncoder(this.passwordEncoder);
				}
				return manager;
			}
			return null;
		}
	}

	private static DataBuffer toDataBuffer(String body) {
		DataBuffer buffer = new DefaultDataBufferFactory().allocateBuffer();
		buffer.write(body.getBytes(StandardCharsets.UTF_8));
		return buffer;
	}

	@RestController
	public static class Http200RestController {
		@RequestMapping("/**")
		@ResponseStatus(HttpStatus.OK)
		public String ok() {
			return "ok";
		}
	}
}
