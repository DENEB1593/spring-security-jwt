package org.deneb.jwt.security;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

@Slf4j
@AllArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // JWT 토큰 추출 및 검증 필터 구현
        String token = jwtTokenProvider.resolveToken(request);
        log.info("jwt token 추출 완료 : {}", token);
        log.info("jwt token 검증");
        if (Objects.nonNull(token) && jwtTokenProvider.validateToken(token)) {
            Authentication authentication =jwtTokenProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.info("jwt token 검증 완료");
        }

        filterChain.doFilter(request, response);

    }
}
