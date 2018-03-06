package sample;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.HttpBasicServerAuthenticationEntryPoint;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * @author Rob Winch
 */
public class SimpleExceptionTranslationWebFilter implements WebFilter {
	private ServerAuthenticationEntryPoint authenticationEntryPoint = new HttpBasicServerAuthenticationEntryPoint();

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return chain.filter(exchange)
			.onErrorResume(AccessDeniedException.class, denied -> commenceAuthentication(exchange, denied)
		);
	}

	private <T> Mono<T> commenceAuthentication(ServerWebExchange exchange, AccessDeniedException denied) {
		return this.authenticationEntryPoint.commence(exchange, new AuthenticationCredentialsNotFoundException("Not Authenticated", denied))
				.then(Mono.empty());
	}
}
