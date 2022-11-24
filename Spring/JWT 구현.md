# JWT 구현

# 사전 작업

## 의존 라이브러리 추가

```groovy
dependencies {
	implementation 'org.springframework.boot:spring-boot-starter-security' // (1)

  // (2) JWT 기능을 위한 jjwt 라이브러리
	implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
	runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.5'
	runtimeOnly	'io.jsonwebtoken:jjwt-jackson:0.11.5'
}
```

- (1) Spring Security 적용하기위해 추가
- (2) JWT을 적용하기 위한 jjwt 라이브러리 추가

## SecurityConfiguration 추가

```java
package com.codestates.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
public class SecurityConfiguration {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http
                // 동일 origin으로부터 들어오는 request만 페이지로 허용한다.
                .headers().frameOptions().sameOrigin()
                .and()
                .csrf().disable()
                // corsConfigurationSource를 이용해 CorsFilter를 적용하여 CORS를 처리한다.
                .cors(Customizer.withDefaults())
                .formLogin().disable()  // 폼 로그인과 관련된 Security Filter 비동기화
                .httpBasic().disable()  // HTTP Basic과 관련된 Security Filter 비동기화
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().permitAll());
        return http.build();
    }

    // PasswordEncoder 객체 생성
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // CorsConfiguration을 통해 구체적인 CORS 정책 설정
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        // 파라미터로 지정한 HTTP Method에 대한 HTTP 통신을 허용한다.
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PATCh", "DELETE"));

        // CorsConfigurationSource 인터페이스의 구현 클래스인 UrlBasedCorsCOnfigurationSource 클래스의 객체를 생성한다.
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // 모든 URL에 앞에서 구성한 CORS 정책(CorsConfiguration)을 적용한다.
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
```

## 회원 가입 로직 수정

### [MemberDto.Post](http://MemberDto.Post) 클래스에 패스워드 필드 추가

```java
package com.codestates.member.dto;

import com.codestates.member.entity.Member;
import com.codestates.stamp.Stamp;
import com.codestates.validator.NotSpace;
import lombok.AllArgsConstructor;
import lombok.Getter;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;

public class MemberDto {
    @Getter
    @AllArgsConstructor
    public static class Post {
        @NotBlank
        @Email
        private String email;

        // 패스워드 필드 추가
        @NotBlank
        private String password;

        @NotBlank(message = "이름은 공백이 아니어야 합니다.")
        private String name;

        @Pattern(regexp = "^010-\\d{3,4}-\\d{4}$",
                message = "휴대폰 번호는 010으로 시작하는 11자리 숫자와 '-'로 구성되어야 합니다.")
        private String phone;
    }

...
...

}
```

- 회원 등록 시, 회원의 패스워드 정보를 전달 받기 위해 password 필드 추가
    - 실제 서비스에서는 사용자가 회원 가입 시, 패스워드가 맞는지 재확인하기 위해 패스워드 입력 확인 필드가 추가로 존재하는 경우가 대부분이다. 입력한 두 패스워드가 일치하는지를 검증하는 로직이 필요하다.
    - 패스워드의 생성 규칙(대/소문자, 패스워드 길이, 특수 문자 포함 여부 등)에 대한 유효성 검증도 실시한다.

### Member 엔티티 클래스에 패스워드 필드 추가

```java
package com.codestates.member.entity;

import com.codestates.audit.Auditable;
import com.codestates.order.entity.Order;
import com.codestates.stamp.Stamp;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@NoArgsConstructor
@Getter
@Setter
@Entity
public class Member extends Auditable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long memberId;

    @Column(nullable = false, updatable = false, unique = true)
    private String email;

    @Column(length = 100, nullable = false)
    private String name;

    // 패스워드 필드 추가. 암호화 되어 저장되기 때문에 컬럼의 길이는 100으로 지정
    @Column(length = 100, nullable = false)
    private String password;

    // @ElementCollection 애너테이션을 이용해 사용자 등록 시, 사용자의 권한을 등록하기 위한 권한 테이블을 생성한다.
    @ElementCollection(fetch = FetchType.EAGER)
    private List<String> roles = new ArrayList<>();

    ...
		...
}
```

### MemberService 사용자 등록 시, 패스워드와 사용자 권한 저장

```java
@Transactional
@Service
public class MemberService {
    private final MemberRepository memberRepository;
    private final ApplicationEventPublisher publisher;
    private final PasswordEncoder passwordEncoder;
    private final CustomAuthorityUtils authorityUtils;

    // 생성자 DI용 파라미터 추가
    public MemberService(MemberRepository memberRepository, ApplicationEventPublisher publisher, PasswordEncoder passwordEncoder, CustomAuthorityUtils authorityUtils) {
        this.memberRepository = memberRepository;
        this.publisher = publisher;
        this.passwordEncoder = passwordEncoder;
        this.authorityUtils = authorityUtils;
    }

    public Member createMember(Member member) {
        verifyExistsEmail(member.getEmail());

        // Password를 단방향 암호화한다.
        String encryptedPassword = passwordEncoder.encode(member.getPassword());
        member.setPassword(encryptedPassword);

        // 등록하는 사용자의 권한 정보를 생성하여 DB에 User Role 저장
        List<String> roles = authorityUtils.createRoles(member.getEmail());
        member.setRoles(roles);

        Member savedMember = memberRepository.save(member);

        publisher.publishEvent(new MemberRegistrationApplicationEvent(this, savedMember));
        return savedMember;
    }
```

### CustomAuthorityUtils

```java
package com.codestates.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class CustomAuthorityUtils {
    @Value("${mail.address.admin")
    private String adminMailAddress;

    private final List<GrantedAuthority> ADMIN_ROLES = AuthorityUtils.createAuthorityList("ROLE_ADMIN", "ROLE_USER");
    private final List<GrantedAuthority> USER_ROLES = AuthorityUtils.createAuthorityList("ROLE_USER");
    private final List<String> ADMIN_ROLES_STRING = List.of("ADMIN", "USER");
    private final List<String> USER_ROLES_STRING = List.of("USER");

    // 메모리 상의 Role을 기반으로 권한 정보 생성
    public List<GrantedAuthority> createAuthorities(String email) {
        if (email.equals(adminMailAddress)) {
            return ADMIN_ROLES;
        }
        return USER_ROLES;
    }

    // DB에 저장된 Role을 기반으로 권한 정보 생성
    public List<GrantedAuthority> createAuthorities(List<String> roles) {
        List<GrantedAuthority> authorities = roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());
        return authorities;
    }

    // DB 저장용
    public List<String> createRoles(String email) {
        if (email.equals(adminMailAddress)) {
            return ADMIN_ROLES_STRING;
        }
        return USER_ROLES_STRING;
    }
}
```

# JWT 자격 증명을 위한 로그인 인증 구현

### 로그인 인증 흐름

1. 클라이언트가 서버 측에 로그인 인증 요청(Username/Password를 서버 측에 전송)
2. 로그인 인증을 담당하는 Security Filter(`JwtAuthenticationFilter`)가 클라이언트의 로그인 인증 정보 수신
3. Security Filter가 수신한 로그인 인증 정보를 AuthenticationManager에게 전달해 인증 처리를 위임
4. AuthenticationManager가 Custom UserDetailsService(`MemberDetailsService`)에게 사용자의 UserDetails 조회를 위임
5. Custom UserDetailsService(`MemberDetailsService`)가 사용자의 크리덴셜을 DB에서 조회한 후, AuthenticationManager에게 사용자의 UserDetails를 전달
6. AuthenticationManager가 로그인 인증 정보와 UserDetails의 정보를 비교해 인증 처리
7. JWT 생성 후, 클라이언트의 응답으로 전달

## Custom UserDetailsService 구현

- Spring Security에서 사용자의 로그인 인증을 처리하는 가장 단순하고 효과적인 방법은 데이터베이스에서 사용자의 크리덴셜을 조회한 후, 조회한 크리덴셜을 AuthenticationManager에게 전달하는 Custom UserDetailsService를 구현하는 것이다.

### MemberDetailsService

```java
package com.codestates.auth.userdetails;

import com.codestates.auth.CustomAuthorityUtils;
import com.codestates.exception.BusinessLogicException;
import com.codestates.exception.ExceptionCode;
import com.codestates.member.entity.Member;
import com.codestates.member.repository.MemberRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Optional;

@Component
public class MemberDetailsService implements UserDetailsService {
    private final MemberRepository memberRepository;
    private final CustomAuthorityUtils authorityUtils;

    public MemberDetailsService(MemberRepository memberRepository, CustomAuthorityUtils authorityUtils) {
        this.memberRepository = memberRepository;
        this.authorityUtils = authorityUtils;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<Member> optionalMember = memberRepository.findByEmail(username);
        Member member = optionalMember.orElseThrow(() -> new BusinessLogicException(ExceptionCode.MEMBER_NOT_FOUND));

        return new MemberDetails(member);
    }

    private final class MemberDetails extends Member implements UserDetails {

        MemberDetails(Member member) {
            setMemberId(member.getMemberId());
            setEmail(member.getEmail());
            setPassword(member.getPassword());
            setRoles(member.getRoles());
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return authorityUtils.createAuthorities(this.getRoles());
        }

        @Override
        public String getUsername() {
            return getEmail();
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }
    }
}
```

- 로그인 인증 기능은 `UsernamePasswordAuthenticationFilter` 로 구현하는 방법 외에도 몇 가지 방법이 더 있다.
    - `OncePerRequestFilter`
    - Controller에서 API 엔드포인트로 구현
- 어떤 방법이 더 좋다라기보다, 애플리케이션 서비스의 요구 사항에 적절한 방법을 선택해서 구현할 수 있음을 기억하자

### 로그인 인증 정보 역직렬화(Deserialization)를 위한 LoginDTO 클래스 생성

```java
// 클라이언트가 전송한 Username/Password 정보를 Security Filter에서 사용할 수 있도록 역직렬화하기 위한 DTO 클래스
@Getter
public class LoginDto {
    private String username;
    private String password;
}
```

### JWT를 생성하는 JwtTokenizer 구현

> JwtTokenizer 클래스는 로그인 인증에 성공한 클라이언트에게 JWT를 생성 및 발급하고 클라이언트의 요청이 들어올 때마다 전달된 JWT를 검증하는 역할을 한다.
> 

```java
package com.codestates.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

@Component
public class JwtTokenizer {
    // JWT 생성 시 필요한 정보들. application.yml 파일에서 로드한다.
    // JWT 생성 및 검증 시 사용되는 Secret Key 정보
    @Getter
    @Value("${jwt.secret-key}")
    private String secretKey;

    // Access Token에 대한 만료 시간 정보
    @Getter
    @Value("${jwt.access-token-expiration-minutes}")
    private int accessTokenExpirationMinutes;

    // Refresh Token에 대한 만료 시간 정보
    @Getter
    @Value("${jwt.refresh-token-expiration-minutes}")
    private int refreshTokenExpirationMinutes;

    public String encodeBase64SecretKey(String secretKey) {
        return Encoders.BASE64.encode(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(Map<String, Object> claims,
                                      String subject,
                                      Date expiration,
                                      String base64EncodedSecretKey) {
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(Calendar.getInstance().getTime())
                .setExpiration(expiration)
                .signWith(key)
                .compact();
    }

    public String generateRefreshToken(String subject,
                                      Date expiration,
                                      String base64EncodedSecretKey) {
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(Calendar.getInstance().getTime())
                .setExpiration(expiration)
                .signWith(key)
                .compact();
    }

    public Jws<Claims> getClaims(String jws, String base64EncodedSecretKey) {
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        Jws<Claims> claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(jws);

        return claims;
    }

    public void verifySignature(String jws, String base64EncodedSecretKey) {
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(jws);
    }

    // JWT의 만료 일시를 지정하기 위한 메서드. JWT 생성 시 사용된다.
    public Date getTokenExpiration(int expirationMinutes) {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MINUTE, expirationMinutes);
        Date expiration = calendar.getTime();

        return expiration;
    }

    private Key getKeyFromBase64EncodedKey(String base64EncodedSecretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(base64EncodedSecretKey);
        Key key = Keys.hmacShaKeyFor(keyBytes);
    }
}
```

### application.yml

```yaml
...
...

jwt:
  key-secret: ${JWT_SECRET_KEY}               # 민감한 정보는 시스템 환경 변수에서 로드한다.
  access-token-expiration-minutes: 30
  refresh-token-expiration-minutes: 420
```

- JWT의 서명에 사용되는 Secret Key 정보는 민감한(sensitive) 정보이므로 시스템 환경 변수의 변수로 등록합니다.
    - ${JWT_SECRET_KEY}는 단순한 문자열이 아니라 OS의 시스템 환경 변수의 값을 읽어오는 일종의 표현식이다.
    - Windows의 경우 아래의 그림과 같이 환경 변수를 설정할 수 있습니다.
    
    [https://itvillage.tistory.com/47](https://itvillage.tistory.com/47)
    

<aside>
💡 이 부분 문제 있음. 우선 아래 방식으로 처리

</aside>

```yaml
...
...

jwt:
  key-secret: CHANBIN123412314123412314123412341234             # 민감한 정보는 시스템 환경 변수에서 로드한다.
  access-token-expiration-minutes: 30
  refresh-token-expiration-minutes: 420
```

## 로그인 인증 요청을 처리하는 Custom Security Filter 구현

```java
package com.codestates.auth.filter;

import com.codestates.auth.jwt.JwtTokenizer;
import com.codestates.dto.LoginDto;
import com.codestates.member.entity.Member;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

// 클라이언트의 로그인 인증 요청을 처리하는 엔트리포인트의 역할을 한다.
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // 로그인 인증 정보(username/password)를 전달 받아 UserDetailsService와 인터렉션 한 뒤 인증 여부를 판단
    private final AuthenticationManager authenticationManager;

    // 클라이언트가 인증에 성공할 경우, JWT를 생성 및 발급하는 역할
    private final JwtTokenizer jwtTokenizer;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, JwtTokenizer jwtTokenizer) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenizer = jwtTokenizer;
    }

    @SneakyThrows
    @Override
    // 메서드 내부에서 인증을 시도하는 로직
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // DTO 클래스로 역질렬화하기 위해 ObjetMapper 인스턴스를 생성
        ObjectMapper objectMapper = new ObjectMapper();

        // ServletInputStream을 LoginDTO클래스로 역직렬화
        LoginDto loginDto = objectMapper.readValue(request.getInputStream(), LoginDto.class);

        // username과 password 정보를 포함한 UsernamePasswordAuthenticationToken 생성
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        // UsernamePasswordAuthenticationToken을 AuthenticationManager에게 전달하면서 인증 처리를 위임
        return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    // 클라이언트의 인증 정보를 이용해 인증에 성공할 경우 호출
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) {
        // Member 엔티티 클래스의 객체를 얻는다.
        // 인증에 성공하면 인증된 Authentication 객체가 생성되면서 principal필드에 Member 객체가 할당된다.
        Member member = (Member) authResult.getPrincipal();

        // Access Token을 생성
        String accessToken = delegatingAccessToken(member);
        // Refresh Token을 생성
        String refreshToken = delegatingRefreshToken(member);

        // Access Token과 Refresh Token을 생성하는 구체적인 로직
        response.setHeader("Authorization", "Bearer " + accessToken);
        response.setHeader("Refresh", refreshToken);
    }

    private String delegatingAccessToken(Member member) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", member.getEmail());
        claims.put("roles", member.getRoles());

        String subject = member.getEmail();
        Date expiration = jwtTokenizer.getTokenExpiration(jwtTokenizer.getAccessTokenExpirationMinutes());

        String base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey());

        String accessToken = jwtTokenizer.generateAccessToken(claims, subject, expiration, base64EncodedSecretKey);

        return accessToken;
    }

    private String delegatingRefreshToken(Member member) {
        String subject = member.getEmail();
        Date expiration = jwtTokenizer.getTokenExpiration(jwtTokenizer.getRefreshTokenExpirationMinutes());
        String base64EncodedSercretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey());

        String refreshToken = jwtTokenizer.generateRefreshToken(subject, expiration, base64EncodedSercretKey);

        return refreshToken;
    }
}
```

## Custom Filter 추가를 위한 SecurityConfiguration 설정 추가

```java
package com.codestates.config;

import com.codestates.auth.filter.JwtAuthenticationFilter;
import com.codestates.auth.jwt.JwtTokenizer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfiguration {
    private final JwtTokenizer jwtTokenizer;

    public SecurityConfiguration(JwtTokenizer jwtTokenizer) {
        this.jwtTokenizer = jwtTokenizer;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // 동일 origin으로부터 들어오는 request만 페이지로 허용한다.
                .headers().frameOptions().sameOrigin()
                .and()
                .csrf().disable()
                // corsConfigurationSource를 이용해 CorsFilter를 적용하여 CORS를 처리한다.
                .cors(withDefaults())
                .formLogin().disable()  // 폼 로그인과 관련된 Security Filter 비동기화
                .httpBasic().disable()  // HTTP Basic과 관련된 Security Filter 비동기화
                // 커스터마이징 된 FilterConfigurer을 추가
                .apply(new CustomFilterConfigurer())
                .and()
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().permitAll()
                );
        return http.build();
    }

    // PasswordEncoder 객체 생성
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // CorsConfiguration을 통해 구체적인 CORS 정책 설정
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        // 파라미터로 지정한 HTTP Method에 대한 HTTP 통신을 허용한다.
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PATCh", "DELETE"));

        // CorsConfigurationSource 인터페이스의 구현 클래스인 UrlBasedCorsCOnfigurationSource 클래스의 객체를 생성한다.
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // 모든 URL에 앞에서 구성한 CORS 정책(CorsConfiguration)을 적용한다.
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    // JwtAuthenticationFilter를 등록하는 역할을 하는 클래스
    public class CustomFilterConfigurer extends AbstractHttpConfigurer<CustomFilterConfigurer, HttpSecurity> {

        // configurer() 메서드를 오버라이드해서 Configuration을 커스터마이징할 수 있다.
        @Override
        public void configure(HttpSecurity builder) throws Exception {
            // AuthenticationManager의 객체를 얻을 수 있다.
            AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
            // JwtAuthenticationFilter를 생성하면서 JwtAuthenticationFilter에서 사용되는 AuthenticationManager와 JwtTokenizer를 DI해준다.
            JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager, jwtTokenizer);
            // 디폴트 request URL인 "/login"을 "/v11/auth/login"으로 변경
            jwtAuthenticationFilter.setFilterProcessesUrl("/v11/auth/login");

            // JwtAuthenticationFilter를 Spring Security Filter Chain에 추가한다.
            builder.addFilter(jwtAuthenticationFilter);
        }
    }
}
```

# 로그인 인증 테스트

![Untitled](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/4e58cae4-2ae9-47a3-acb2-164909161971/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221124%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221124T142445Z&X-Amz-Expires=86400&X-Amz-Signature=b20b72967fefb4d0e0ac459363bdd29af4d681e2802b46ad4e8c0adf77fe1274&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject)

## 로그인 인증 요청

![Untitled](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/70fb826f-d746-4fe3-9756-c763b79f793d/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221124%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221124T142456Z&X-Amz-Expires=86400&X-Amz-Signature=4095acc118b06808e373e09830d635f803a94eba231b6ccc3d971c5a744583f7&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject)

- SecurityConfiguration에서 변경한  URL(`/v11/auth/login`)로 로그인 인증 REQUEST를 전송해야 한다.
- 로그인 인증이 성공하면 Headers 탭에서 Authorization 키의 값으로 AccessToken이, Refresh 키의 값으로 Refresh Token이 포함되는 것을 알 수 있다.
- 클라이언트에서는 request를 전송할 때마다 전달 받은 JWT를 request header에 포함 후, 클라이언트의 자격 증명 정보로 사용하면 된다.

# 로그인 인증 성공 및 실패에 따른 추가 처리

- `AuthenticationSuccessHandler` : 로그인 인증에 성공했을 때, 로그를 기록한다거나 로그인에 성공한 사용자 정보를 response로 전송하는 등의 추가 처리를 할 수 있는 핸들러
- `AuthenticationFailureHandler` : 로그인 인증 실패에 대해 추가 처리를 할 수 있는 핸들러

### AuthenticationSuccessHandler 구현

```java
package com.codestates.auth.handler;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class MemberAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    // AuthenticationSuccessHandler 인터페이스를 구현해야 한다.
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // 인증 성공 후, 로그를 기록하거나 사용자 정보를 response로 전송하는 등의 추가 작업을 할 수 있다.
        log.info("# Authenticated successfully!");
    }
}
```

### AuthentcationFailureHandler 구현

```java
package com.codestates.auth.handler;

import com.codestates.response.ErrorResponse;
import com.google.gson.Gson;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class MemberAuthenticationFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        log.error("# Authentication failed: {}", exception.getMessage());

        sendErrorResponse(response);
    }

    // 출력 스트림에 Error 정보를 담는 메서드
    private void sendErrorResponse(HttpServletResponse response) throws IOException {
        // JSON 문자열로 변환하는데 사용되는 Gson 라이브러리 인스턴스 생성
        Gson gson = new Gson();
        // UNAUTHORIZED(401) 상태 코드는 인증에 실패할 경우 전달할 수 있는 HTTP status이다.
        ErrorResponse errorResponse = ErrorResponse.of(HttpStatus.UNAUTHORIZED);
        // response Content Type이 application/json 이라는 것을 전달
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        // response statusrk 401임을 클라이언트에게 전달
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        // Gson을 이용해 ErrorResponse 객체를 JSON 포맷 문자열로 변환 후, 출력 스트림을 생성
        response.getWriter().write(gson.toJson(errorResponse, ErrorResponse.class));
    }
}
```

## AuthenticationSuccessHandler와 AuthenticationFailureHandler 추가

- `JwtAuthenticationFilter` 에 등록하면 로그인 인증 시, 두 핸들러를 사용할 수 있다.

```java

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfiguration {
    private final JwtTokenizer jwtTokenizer;

    public SecurityConfiguration(JwtTokenizer jwtTokenizer) {
        this.jwtTokenizer = jwtTokenizer;
    }

    ...
		...
    
		// JwtAuthenticationFilter를 등록하는 역할을 하는 클래스
    public class CustomFilterConfigurer extends AbstractHttpConfigurer<CustomFilterConfigurer, HttpSecurity> {

        // configurer() 메서드를 오버라이드해서 Configuration을 커스터마이징할 수 있다.
        @Override
        public void configure(HttpSecurity builder) throws Exception {
            // AuthenticationManager의 객체를 얻을 수 있다.
            AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
            // JwtAuthenticationFilter를 생성하면서 JwtAuthenticationFilter에서 사용되는 AuthenticationManager와 JwtTokenizer를 DI해준다.
            JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager, jwtTokenizer);
            // 디폴트 request URL인 "/login"을 "/v11/auth/login"으로 변경
            jwtAuthenticationFilter.setFilterProcessesUrl("/v11/auth/login");

            // AuthenticationSuccessHandler와 AuthenticationFailureHandler 추가
            jwtAuthenticationFilter.setAuthenticationSuccessHandler(new MemberAuthenticationSuccessHandler());
            jwtAuthenticationFilter.setAuthenticationFailureHandler(new MemberAuthenticationFailureHandler());
            
            // JwtAuthenticationFilter를 Spring Security Filter Chain에 추가한다.
            builder.addFilter(jwtAuthenticationFilter);
        }
    }
}
```

- Spring에서는 객체를 생성할 때 new 키워드 사용을 자제하는 것이 좋다.
- 여기서는 두 구현 클래스가 다른 Security Filter에서도 사용된다면 ApplicationContext에 Bean으로 등록해서 DI 받는게 맞다.
- 하지만 Security Filter마다 각각의 구현 클래스를 생성할 것이라면 new 키워드를 사용해서 객체를 생성해도 무방하다.

### AuthenticationSuccessHandler 호출

- jwtAuthenticationFilter에서 AuthenticationSuccessHandler와 AuthenticationFailureHandler를 호출해서 사용하기만 하면 된다.

```java
package com.codestates.auth.filter;

import com.codestates.auth.jwt.JwtTokenizer;
import com.codestates.dto.LoginDto;
import com.codestates.member.entity.Member;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

// 클라이언트의 로그인 인증 요청을 처리하는 엔트리포인트의 역할을 한다.
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    ...
		...

    @Override
    // 클라이언트의 인증 정보를 이용해 인증에 성공할 경우 호출
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws ServletException, IOException {
        // Member 엔티티 클래스의 객체를 얻는다.
        // 인증에 성공하면 인증된 Authentication 객체가 생성되면서 principal필드에 Member 객체가 할당된다.
        Member member = (Member) authResult.getPrincipal();

        // Access Token을 생성
        String accessToken = delegatingAccessToken(member);
        // Refresh Token을 생성
        String refreshToken = delegatingRefreshToken(member);

        // Access Token과 Refresh Token을 생성하는 구체적인 로직
        response.setHeader("Authorization", "Bearer " + accessToken);
        response.setHeader("Refresh", refreshToken);

        // onAuthenticationSuccess() 메서드를 호출하면 MemberAuthenticationSuccessHandler의 onAuthenticationSuccess() 메서드가 호출된다.
        this.getSuccessHandler().onAuthenticationSuccess(request, response, authResult);
    }

    ...
		...

}
```

- AuthenticationFailureHandler는 별도의 코드를 추가하지 않아도 로그인 인증에 실패하면 MemberAuthenticationFailureHandler의 onAuthenticationFailure() 메서드가 알아서 호출된다.

### 로그인 인증 성공했을 때 로그

```java
2022-11-24 20:24:56.575  INFO 68490 --- [nio-8080-exec-3] c.a.h.MemberAuthenticationSuccessHandler : # Authenticated successfully!
```

### 로그인 인증 실패했을 때

![스크린샷 2022-11-24 오후 8.25.47.png](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/6a70a782-1497-47f5-98b5-3e2c55df51c1/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2022-11-24_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_8.25.47.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221124%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221124T142616Z&X-Amz-Expires=86400&X-Amz-Signature=9476de58adfccc3c35dbf7e69310ea25fb87f60d4530af2da5d41fd0820d36db&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA%25202022-11-24%2520%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE%25208.25.47.png%22&x-id=GetObject)

```java
2022-11-24 20:25:18.421 ERROR 68490 --- [nio-8080-exec-4] c.a.h.MemberAuthenticationFailureHandler : # Authentication failed: 자격 증명에 실패하였습니다.
```

# JWT 검증 기능 구현

- 로그인 인증을 성공적으로 수행하면 response header(`Authorization` , `Refresh`)를 통해 JWT를 전달 받을 수 있다.

## JWT 검증 필터 구현

- JWT를 검증을 위해 가장 먼저 해야될 작업은 JWT를 검증하는 전용 Security Filter를 구현하는 것이다.

### JwVerificationFilter

```java
package com.codestates.auth.filter;

import com.codestates.auth.jwt.JwtTokenizer;
import com.codestates.auth.utils.CustomAuthorityUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;

public class JwtVerificationFilter extends OncePerRequestFilter {  // (1)
    private final JwtTokenizer jwtTokenizer;
    private final CustomAuthorityUtils authorityUtils;

    // (2)
    public JwtVerificationFilter(JwtTokenizer jwtTokenizer,
                                 CustomAuthorityUtils authorityUtils) {
        this.jwtTokenizer = jwtTokenizer;
        this.authorityUtils = authorityUtils;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Map<String, Object> claims = verifyJws(request); // (3)
        setAuthenticationToContext(claims);      // (4)

        filterChain.doFilter(request, response); // (5)
    }

    // (6)
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String authorization = request.getHeader("Authorization");  // (6-1)

        return authorization == null || !authorization.startsWith("Bearer");  // (6-2)
    }

    private Map<String, Object> verifyJws(HttpServletRequest request) {
        String jws = request.getHeader("Authorization").replace("Bearer ", ""); // (3-1)
        String base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey()); // (3-2)
        Map<String, Object> claims = jwtTokenizer.getClaims(jws, base64EncodedSecretKey).getBody();   // (3-3)

        return claims;
    }

    private void setAuthenticationToContext(Map<String, Object> claims) {
        String username = (String) claims.get("username");   // (4-1)
        List<GrantedAuthority> authorities = authorityUtils.createAuthorities((List)claims.get("roles"));  // (4-2)
        Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);  // (4-3)
        SecurityContextHolder.getContext().setAuthentication(authentication); // (4-4)
    }
}
```

- (1) Spring Security에서는 `OncePerRequestFilter` 를 확장해서 request 당 한 번만 실행되는 Security Filter를 구현할 수 있다.
    
    JWT 검증은 request 당  한 번만 수행하면 되기 때문에 JWT 전용 Filter로 만들기에 `OncePerRequestFilter` 를 이용하는 것이 적절하다고 볼 수 있다. (성공이냐 실패냐만 판단하면 되기 때문)
    
- (2) JwtTokenizer와 CustomAuthorityUtils를 DI 받는다.
    - `JwtTokenizer` : JWT를 검증하고 Claims(토큰에 포함된 정보)를 얻는데 사용된다.
    - `CustomAuthorityUtils` : JWT 검증에 성공하면 Authentication 객체에 채울 사용자의 권한을 생성하는데 사용된다.
- (3) `verifyJws()` : JWT를 검증하는데 사용되는 private 메서드
    - (3-1) JWT를 request header에 추가해서 서버 측에 전송. jws는 JSON Web Token Signed를 의미한다.
    - (3-2) JWT 서명(Signature)을 검증하기 위한 Secret Key를 얻는다.
    - (3-3) JWT에서 Claims를 파싱한다. JWT에서 Claims를 파싱할 수 있다는 의미는 내부적으로 서명(Signature) 검증에 성공했다는 의미이다.
        
        즉, verify() 같은 검증 메서드가 따로 존재하는 것이 아니라 Claims가 정상적으로 파싱이 되면서 서명 검증 역시 자연스럽게 성공했다라는 뜻이다.
        
- (4) `setAuthenticaitonToContext()` : Authentication 객체를 SecurityContext에 저장하기 위한 private 메서드
    - (4-1) JWT에서 파싱한 Claims에서 username을 얻는다.
    - (4-2) JWT의 Claims에서 얻은 권한 정보를 기반으로 `List<GrantedAuthority>` 를 생성한다.
    - (4-3) username과 List<GrantedAuthority>를 포함한 Authentication 객체를 생성한다.
    - (4-4) SecurityContext에 Authentication 객체를 저장한다.
- (5) 다음 Security Filter 호출
- (6) OnePerRequestFilter의 `shouldNotFilter()` 를 오버라이드한 것으로, 특정 조건에 부합하면 Filter의 동작을 수행하지 않고 다음 FIlter로 건너뛰도록 해준다.
    - (6-1) Authorization header 값을 얻은 후에
    - (6-2) Authorization header의 값이 null이거나 Authroization header의 값이 “Bearer”로 시작하지 않는다면 Filter의 동작을 수행하지 않음
        
        즉, JWT 자격 증명이 피요하지 않은 리소스에 대한 요청이라고 판단하고 다음 Filter로 처리르 넘기는 것이다.
        

## SecurityConfiguration 설정 업데이트

- JwtVerificationFilter를 사용하기 위해서는 아래와 같은 설정을 SecurityConfiguration에 추가해야 한다.
    - 세션 정책 설정 추가
    - JwtVerificationFilter 추가

```java

@Configuration
public class SecurityConfiguration {
    private final JwtTokenizer jwtTokenizer;
    private final CustomAuthorityUtils authorityUtils;

    public SecurityConfiguration(JwtTokenizer jwtTokenizer, CustomAuthorityUtils authorityUtils) {
        this.jwtTokenizer = jwtTokenizer;
        this.authorityUtils = authorityUtils;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // 동일 origin으로부터 들어오는 request만 페이지로 허용한다.
                .headers().frameOptions().sameOrigin()
                .and()
                .csrf().disable()
                // corsConfigurationSource를 이용해 CorsFilter를 적용하여 CORS를 처리한다.
                .cors(withDefaults())
                // (1) 세션을 생성하지 않도록 설정
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .formLogin().disable()  // 폼 로그인과 관련된 Security Filter 비동기화
                .httpBasic().disable()  // HTTP Basic과 관련된 Security Filter 비동기화
                // 커스터마이징 된 FilterConfigurer을 추가
                .apply(new CustomFilterConfigurer())
                .and()
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().permitAll()
                );
        return http.build();
    }

    // PasswordEncoder 객체 생성
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // CorsConfiguration을 통해 구체적인 CORS 정책 설정
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        // 파라미터로 지정한 HTTP Method에 대한 HTTP 통신을 허용한다.
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PATCh", "DELETE"));

        // CorsConfigurationSource 인터페이스의 구현 클래스인 UrlBasedCorsCOnfigurationSource 클래스의 객체를 생성한다.
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // 모든 URL에 앞에서 구성한 CORS 정책(CorsConfiguration)을 적용한다.
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    // JwtAuthenticationFilter를 등록하는 역할을 하는 클래스
    public class CustomFilterConfigurer extends AbstractHttpConfigurer<CustomFilterConfigurer, HttpSecurity> {

        // configurer() 메서드를 오버라이드해서 Configuration을 커스터마이징할 수 있다.
        @Override
        public void configure(HttpSecurity builder) throws Exception {
            // AuthenticationManager의 객체를 얻을 수 있다.
            AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
            // JwtAuthenticationFilter를 생성하면서 JwtAuthenticationFilter에서 사용되는 AuthenticationManager와 JwtTokenizer를 DI해준다.
            JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager, jwtTokenizer);
            // 디폴트 request URL인 "/login"을 "/v11/auth/login"으로 변경
            jwtAuthenticationFilter.setFilterProcessesUrl("/v11/auth/login");
            // AuthenticationSuccessHandler와 AuthenticationFailureHandler 추가
            jwtAuthenticationFilter.setAuthenticationSuccessHandler(new MemberAuthenticationSuccessHandler());
            jwtAuthenticationFilter.setAuthenticationFailureHandler(new MemberAuthenticationFailureHandler());
							
						
            // (2) JwtVerificationFilter의 인스턴스를 생성하면서 JwtVerification에서 사용되는 개체들을 생성자로 DI 해준다.
            JwtVerificationFilter jwtVerificationFilter = new JwtVerificationFilter(jwtTokenizer, authorityUtils);

            // JwtAuthenticationFilter를 Spring Security Filter Chain에 추가한다.
            builder.addFilter(jwtAuthenticationFilter)
                    // (3) jwtVerificationFilter가 JwtAuthenticationFilter 바로 뒤에 동작하도록 뒤에 추가
                    .addFilterAfter(jwtVerificationFilter, JwtAuthenticationFilter.class);
        }
    }
}
```

- (1)`.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)`
를 통해서 세션을 생성하지 않도록 설정한다.
    - stateless한 애플리케이션을 유지하기 위해 세션 유지 시간을 아주 짧게 가젹기 위한 (거의 무상태) 설정을 추가한 것
- `SessionCreateionPolicy` 의 설정 값으로는 아래와 같이 총 네 개의 값을 사용할 수 있다.
    - `SessionCreationPolicy.*ALWAYS*`
        - 항상 세션을 생성
    - `SessionCreationPolicy.NEVER`
        - 세션을 생성하지 않지만 만약에 이미 생성된 세션이 있다면 사용
    - `SessionCreationPolicy.*IF_REQUIRED*`
        - 필요한 경우에만 세션을 생성
    - `SessionCreationPolicy.*STATELESS*`
        - 세션을 생성하지 않으며, SecurityContext 정보를 얻기 위해 결코 세션을 사용하지 않는다.
- (2) JwtVerificationFilter의 인스턴스를 생성하면서 JwtVerification에서 사용되는 개체들을 생성자로 DI 해준다.
- (3) jwtVerificationFilter가 JwtAuthenticationFilter 바로 뒤에 동작하도록 뒤에 추가

## 서버 측 리소스에 역할(Role) 기반 권한 적용

- 서버 측 리소스에 적절한 접근 권한 설정을 해주어야 한다.
- JWT를 이용한 자격 증명이라는 의미에는 특정 리소스에 접근할 수 있는 적절한 권한을 가지고 있는지를 판단하는 의미도 포함하고 있기 때문이다.

```java
@Configuration
public class SecurityConfiguration {
    private final JwtTokenizer jwtTokenizer;
    private final CustomAuthorityUtils authorityUtils;

    public SecurityConfiguration(JwtTokenizer jwtTokenizer, CustomAuthorityUtils authorityUtils) {
        this.jwtTokenizer = jwtTokenizer;
        this.authorityUtils = authorityUtils;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // 동일 origin으로부터 들어오는 request만 페이지로 허용한다.
                .headers().frameOptions().sameOrigin()
                .and()
                .csrf().disable()
                // corsConfigurationSource를 이용해 CorsFilter를 적용하여 CORS를 처리한다.
                .cors(withDefaults())
                // 세션을 생성하지 않도록 설정
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .formLogin().disable()  // 폼 로그인과 관련된 Security Filter 비동기화
                .httpBasic().disable()  // HTTP Basic과 관련된 Security Filter 비동기화
                // 커스터마이징 된 FilterConfigurer을 추가
                .apply(new CustomFilterConfigurer())
                .and()
                .authorizeHttpRequests(authorize -> authorize
                        .antMatchers(HttpMethod.POST, "/*/members").permitAll() // (1)
                        .antMatchers(HttpMethod.PATCH, "/*/members/**").hasRole("USER") // (2)
                        .antMatchers(HttpMethod.GET, "/*/members").hasRole("ADMIN") // (3) 
                        .antMatchers(HttpMethod.GET, "/*/members/**").hasAnyRole("USER", "ADMIN") // (4)
                        .antMatchers(HttpMethod.DELETE, "/*/members/**").hasRole("USER") // (5)
                        .anyRequest().permitAll()
                );
        return http.build();
    }
```

- 회원 등록의 경우, 접근 권한 여부와 상관없이 누구나 접근이 가능해야 하므로 (1)과 같이 회원등록에 사용되는 URL(”`/v11/members`”)과 HTTP Method(여기서는 `POST`)에 해당된다면 접근을 허용합니다.
    
    여러분들이 **MemberController의 postMember() 핸들러 메서드**의 URL과 HTTP Method를 확인해본다면 (1)에서 설정한 조건이 이해가 되리라 생각합니다.
    
- 회원 정보 수정의 경우, (2)와 같이 일반 사용자(`USER`) 권한만 가진 사용자만 접근이 가능하도록 허용합니다.
    
    회원 정보 수정 요청을 처리하는 **MemberController의 patchMember() 핸들러 메서드**에 대한 접근 권한 부여 설정이라는 사실을 기억하세요.
    
    `.antMatchers(HttpMethod.PATCH, "/*/members/**")`에서 ‘`**`’는 하위 URL로 어떤 URL이 오더라도 매치가 된다는 의미입니다.
    
- 모든 회원 정보의 목록은 (3)과 같이 관리자(`ADMIN`) 권한을 가진 사용자만 접근이 가능하여야 할 것입니다.
    
    회원 정보 목록 조회 요청을 처리하는 **MemberController의 getMembers() 핸들러 메서드**에 대한 접근 권한 부여 설정에 해당됩니다.
    
- 특정 회원에 대한 정보 조회는 (4)와 같이 일반 사용자(`USER`)와 관리자(`ADMIN`) 권한을 가진 사용자 모두 접근이 가능하면 될 것 같군요.
    
    특정 회원 정보 조회 요청을 처리하는 **MemberController의 getMember() 핸들러 메서드**에 대한 접근 권한 부여 설정에 해당됩니다.
    
- 특정 회원을 삭제하는 요청은 (5)와 같이 해당 사용자가 탈퇴같은 처리를 할 수 있어야 하므로 일반 사용자(`USER`) 권한만 가진 사용자만 접근이 가능하도록 허용합니다.
    
    특정 회원 정보 삭제 요청을 처리하는 **MemberController의 deleteMember() 핸들러 메서드**에 대한 접근 권한 부여 설정에 해당됩니다.
    

# JWT 검증 테스트

## ****JWT를 Authorization header에 포함하지 않을 경우****

![Untitled](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/4a41ff76-b75d-4522-9214-8f708466b40d/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221124%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221124T142631Z&X-Amz-Expires=86400&X-Amz-Signature=c31c88b4e8c4fcf1495a032d29fd7da87a4ff3c9f3d74156fed4778882865c80&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject)

## ****유효하지 않은 JWT를 Authorization header에 포함할 경우****

![Untitled](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/a75fffac-db2a-4a87-bea3-3b332aa9c258/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221124%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221124T142648Z&X-Amz-Expires=86400&X-Amz-Signature=a311c3b75739791c797c43671b7b17be0e1ba1d467067d1a8cbb6bd99565fe02&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject)

- 접근 권한에 대한 에러를 나타내는 403 status보다는 검증에 실패했기 때문에 자격 증명에 실패한 것과 같으므로 UNAUTHORIZED를 의미하는 401 status가 더 적절할듯

## ****권한이 부여되지 않은 리소스에 request를 전송할 경우****

![Untitled](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/b303d5ed-2662-4a1b-a03a-97ec3d18c1b9/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221124%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221124T142658Z&X-Amz-Expires=86400&X-Amz-Signature=a1030e647d8fa18a387d7673c3ca8f6f677a51e73ebee9b1bb935354c82be57a&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject)

- `JwtVerificationFilter` 에서 JWT의 자격 증명은 정상적으로 수행되었지만 ADMIN 권한이 없는 사용자이므로 403 status가 전달된다.

# 예외 처리

## ****JwtVerificationFilter에 예외 처리 로직 추가****

- JWT에 대한 서명(Signature) 검증에 실패할 경우 throw되는 `SignatureException` 에 대해서 어떤 처리도 하지 않고 있다.
- JWT가 만료될 경우, 발생하는 `ExpiredJwtException` 에 대한 처리도 이루어지지 않았다.

```java
package com.codestates.auth.filter;

import com.codestates.auth.CustomAuthorityUtils;
import com.codestates.auth.jwt.JwtTokenizer;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;

public class JwtVerificationFilter extends OncePerRequestFilter {
    
		...
		...

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // (1)
        try {
            Map<String, Object> claims = verifyJws(request);
            setAuthenticationToContext(claims);
        } catch (SignatureException se) {
            request.setAttribute("exception", se);
        } catch (ExpiredJwtException ee) {
            request.setAttribute("exception", ee);
        } catch (Exception e) {
            request.setAttribute("exception", e);
        }

        filterChain.doFilter(request, response);
    }

    ...
		...

}
```

- (1) try~catch문으로 Exception이 발생되면 HttpServletRequest의 애트리뷰트로 추가된다. 이렇게 추가된 애트리뷰는 AuthenticationEntryPoint에서 사용할 수 있다.
- JwtVerificationFilter 예외 처리의 키포인트는 catch한 Exception을 throw하지 않고 단순히 request.setAttribute()를 설정하는 일 밖에 하지 않는다는 것이다.
    
    이렇게 하면 예외가 발생하고 Security Context에 클라이언트의 인증 정보(Authentication 객체)가 저장되지 않는다. 
    
- SecurityContext에 클라이언트의 인증 정보(Authentication 객체)가 저장되지 않은 상태로 다음(next) Security Filter 로직을 수행하다보면 결국에는 `AuthenticationException`
 이 발생하게 되고, 이 `AuthenticationException`
은 바로 아래에서 설명하는 **AuthenticationEntryPoint**
가 처리하게 된다.
- SecurityContext에 클라이언트의 인증 정보가 채워지지 않은 상태에서 Security Filter 로직을 수행하게되면 `AuthenticationException`
 이 발생한다는 사실을 꼭 기억하자

## AuthenticationEntryPoint 구현

> AuthenticationEntryPoint는 `SignatureException`, `ExpiredJwtException`등 Exception 발생으로 인해 SecurityContext에 Authentication이 저장되지 않을 경우 등 `AuthenticationException`이 발생할 때 호출되는 핸들러 같은 역할을 한다.
> 

### **MemberAuthenticationEntryPoint**

```java
package com.codestates.auth.handler;

import com.codestates.auth.utils.ErrorResponder;
import com.codestates.response.ErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Component
public class MemberAuthenticationEntryPoint implements AuthenticationEntryPoint {
    // 인증 과정에서 AuthenticationException이 발생할 경우 호출되며, 처리하고자 하는 로직을 commence() 메서드에 구현한다.
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        Exception exception = (Exception) request.getAttribute("exception");
        ErrorResponder.sendErrorResponse(response, HttpStatus.UNAUTHORIZED);

        logExceptionMessage(authException, exception);
    }

    private void logExceptionMessage(AuthenticationException authException, Exception exception) {
        String message = exception != null ? exception.getMessage() : authException.getMessage();
        log.warn("Unauthorized error happened: {}", message);
    }
}
```

### ErrorResponder

```java
package com.codestates.auth.utils;

import com.codestates.response.ErrorResponse;
import com.google.gson.Gson;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// ErrorResponse를 출력 스트림으로 생성하는 역할
public class ErrorResponder {
    public static void sendErrorResponse(HttpServletResponse response, HttpStatus status) throws IOException {
        Gson gson = new Gson();
        ErrorResponse errorResponse = ErrorResponse.of(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(status.value());
        response.getWriter().write(gson.toJson(errorResponse, ErrorResponse.class));
    }
}
```

## AccessDeniedHandler 구현

> AccessDeniedHandler는 인증에는 성공했지만 해당 리소스에 대한 권한이 없을 경우 호출되는 핸들러이다.
> 

```java
package com.codestates.auth.handler;

import com.codestates.auth.utils.ErrorResponder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Component
public class MemberAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        ErrorResponder.sendErrorResponse(response, HttpStatus.FORBIDDEN);
        log.warn("Forbidden error happend: {}", accessDeniedException.getMessage());
    }
}
```

- **MemberAccessDeniedHandler** 클래스는 요청한 리소스에 대해 적절한 권한이 없을 경우 호출되는 핸들러로써, 처리하고자 하는 로직을 `handle()`메서드에 구현하면 된다.

## ****SecurityConfiguration에AuthenticationEntryPoint 및 AccessDeniedHandler 추가****

```java
package com.codestates.config;

import com.codestates.auth.CustomAuthorityUtils;
import com.codestates.auth.filter.JwtAuthenticationFilter;
import com.codestates.auth.filter.JwtVerificationFilter;
import com.codestates.auth.handler.MemberAccessDeniedHandler;
import com.codestates.auth.handler.MemberAuthenticationEntryPoint;
import com.codestates.auth.handler.MemberAuthenticationFailureHandler;
import com.codestates.auth.handler.MemberAuthenticationSuccessHandler;
import com.codestates.auth.jwt.JwtTokenizer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfiguration {
    private final JwtTokenizer jwtTokenizer;
    private final CustomAuthorityUtils authorityUtils;

    public SecurityConfiguration(JwtTokenizer jwtTokenizer, CustomAuthorityUtils authorityUtils) {
        this.jwtTokenizer = jwtTokenizer;
        this.authorityUtils = authorityUtils;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // 동일 origin으로부터 들어오는 request만 페이지로 허용한다.
                .headers().frameOptions().sameOrigin()
                .and()
                .csrf().disable()
                // corsConfigurationSource를 이용해 CorsFilter를 적용하여 CORS를 처리한다.
                .cors(withDefaults())
                // 세션을 생성하지 않도록 설정
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .formLogin().disable()  // 폼 로그인과 관련된 Security Filter 비동기화
                .httpBasic().disable()  // HTTP Basic과 관련된 Security Filter 비동기화
                .exceptionHandling()
                .authenticationEntryPoint(new MemberAuthenticationEntryPoint()) // 추기
                .accessDeniedHandler(new MemberAccessDeniedHandler()) // 추가
                .and()
                // 커스터마이징 된 FilterConfigurer을 추가
                .apply(new CustomFilterConfigurer())
                .and()
                .authorizeHttpRequests(authorize -> authorize
                        .antMatchers(HttpMethod.POST, "/*/members").permitAll()
                        .antMatchers(HttpMethod.PATCH, "/*/members/**").hasRole("USER")
                        .antMatchers(HttpMethod.GET, "/*/members").hasRole("ADMIN")
                        .antMatchers(HttpMethod.GET, "/*/members/**").hasAnyRole("USER", "ADMIN")
                        .antMatchers(HttpMethod.DELETE, "/*/members/**").hasRole("USER")
                        .anyRequest().permitAll()
                );
        return http.build();
    }

    ...
		...

}
```

![Untitled](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/6e164406-e01f-4ba4-8686-3b6e9da43064/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221124%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221124T142711Z&X-Amz-Expires=86400&X-Amz-Signature=acd996f098ab24347b9703ac4a81d3defdc4fc811bf9b0e81be5274cbd4ce279&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject)

![Untitled](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/1ff16dc1-a74f-498c-a938-101fe6848d1a/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221124%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221124T142722Z&X-Amz-Expires=86400&X-Amz-Signature=7ef1a8e388e07c73193a28f940ea0bfebf2591a2a40645f995fde0ad81bb965f&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject)

## 정리

- UsernamePasswordAuthenticationFilter를 이용해 JWT 발급 전의 로그인 인증 기능을 구현할 수 있다.
- Spring Security에서는 개발자가 직접 Custom Configuration를 구성해 Spring Security의 Configuration을 커스터마이징할 수 있다.
- Username/Password 기반의 로그인 인증은 `OnePerRequestFilter` 같은 Spring Security에서 지원하는 다른 Filter를 이용해서 구현할 수 있다. Controller에서 REST API 엔드포인트로 구현하는 것도 가능하다.
- Spring Security에서는 Username/password 기반의 로그인 인증에 성공했을 때, 로그를 기록하거나 로그인에 성공한 사용자 정보를 response로 전송하는 등의 추가 처리를 할 수 있는 `AuthenticationSuccessHandler`를 지원하며, 로그인 인증 실패 시에도 마찬가디로 인증 실패에 대해 추가 처리를 할 수 있는 `AuthenticationFailureHandler` 를 지원한다.
- JWT는 **JWS(JSON Web Token Signed)라고도 불리운다.**
- SecurityContext에 Authentication을 저장하게 되면 Spring Security의 세션 정책(Session Policy)에 따라서 세션을 생성할 수도 있고, 그렇지 않을 수도 있다.
- SecurityContext에 클라이언트의 인증 정보(Authentication 객체)가 저장되지 않은 상태로 다음(next) Security Filter 로직을 수행하다보면 결국에는 `AuthenticationException` 이 발생하게 되고, 이 `AuthenticationException`은 **AuthenticationEntryPoint**가 처리하게된다.
- `AccessDeniedHandler`는 인증에는 성공했지만 해당 리소스에 대한 권한이 없을 경우 호출되는 핸들러이다.