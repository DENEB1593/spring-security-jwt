package org.deneb.jwt.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.deneb.jwt.user.UserService;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenProvider implements InitializingBean {

    private final UserService userService;

    @Value("${springboot.jwt.secret}")
    private String secretKey = "secretKey";
    private Key key;
    private static final long tokenValidMillisecond = 1_000L * 60 * 60;

    @Override
    public void afterPropertiesSet() throws Exception {
        log.info("init jwt secretKey start");
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes(StandardCharsets.UTF_8));
        key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
        log.info("init jwt secretKey finish");

    }

    public String createToken(String userUid, List<String> roles) {
        log.info("[createToken] 토큰 생성 시작");
        Claims claims = Jwts.claims().setSubject(userUid);
        claims.put("roles", roles);
        Date now = new Date();

        String token = Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + tokenValidMillisecond))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        log.info("[createToken] 토큰 생성 완료");
        return token;
    }

    public Authentication getAuthentication(String token) {
        log.info("[getAuthentication] 토큰 인증 정보 조회 시작");

        String userName = getUserName(token);
        UserDetails userDetails = userService.loadUserByUsername(userName);

        log.info("[getAuthentication] 사용자 정보 조회 완료 : {}", userDetails.getUsername());

        log.info("[getAuthentication] 토큰 인증 정보 조회 완료");
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    public String getUserName(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public String resolveToken(HttpServletRequest request) {
        log.info("[resolveToken] Http 헤더에서 토근값 추출");
        return request.getHeader("X-AUTH-TOKEN");
    }

    public boolean validateToken(String token) {
        log.info("토근 유효성 검증");
        try {
            Jws<Claims> claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return !claims.getBody().getExpiration().before(new Date());
        } catch (RuntimeException ex) {
            log.debug("토근 일자가 만료되었습니다.");
            return false;
        }
    }
}
