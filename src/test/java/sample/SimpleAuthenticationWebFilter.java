package sample;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class SimpleAuthenticationWebFilter implements WebFilter {
	private Logger logger = LoggerFactory.getLogger(getClass());

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return Mono.just(exchange)
				.publishOn(Schedulers.parallel())
				.filter(e -> e.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION))
				.switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
				.flatMap( token -> authenticate(exchange, chain));
	}

	private Mono<Void> authenticate(ServerWebExchange exchange,
			WebFilterChain chain) {
		SecurityContextImpl securityContext = new SecurityContextImpl();
		this.logger.debug("!!!!!!!!!!!!!!!!!!!!new SecurityContextImpl()!!!!!!!!!!!!!!!!!!!!!!!");
		securityContext.setAuthentication(new UsernamePasswordAuthenticationToken("user", "password",
				AuthorityUtils.createAuthorityList("ROLE_USER")));
		return chain.filter(exchange)
				.subscriberContext(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext)));
	}
}
