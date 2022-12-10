# Spring Boot 서버 Tomcat에서 Jetty로 변경해보기

## Tomcat이 뭐죠?

> Tomcat은 Apache사에서 개발한 서블릿 컨테이너만 있는 오픈소스 웹 애플리케이션 서버이다.
> 
- Tomcat은 자바 애플리케이션을 위한 대표적인 오픈소스 WAS(Web Application Server)이다.
- 오픈소스이기 때문에 라이선스 비용 부담없이 사용할 수 있다.
- 독립적으로도 사용 가능하며 Apache 같은 다른 웹 서버와 연동하여 함께 사용할 수 있다.
- Tomcat은 자바 서블릿 컨테이너에 대한 공식 구현체로, Spring Boot에 내장되어 있어 별도의 설치 과정이 필요하지 않다.

## Tomcat 실행 및 의존성 확인하기

- Gradle 탭에선 프로젝트에서 추가한 의존성 모듈을 모두 확인할 수 있다.
- 서버를 구성하기 위해 추가한 `spring-boot-starter-web`모듈(Spring Web) 토글을 열어보면 `spring-boot-starter-tomcat` 모듈을 포함하고 있는 것을 확인할 수 있다.

## Jetty가 뭐죠?

> Jetty는 이클립스 재단의 HTTP 서버이자 자바 서블릿 컨테이너이다.
> 
- Jetty도 Tomcat과 같이 자바 서블릿 컨테이너이자 서버로 사용할 수 있기 때문에 개발자는 원하는 서버를 선택하여 프로젝트를 구성할 수 있다.
- Jetty는 2009년 이클립스 재단으로 이전하여 오픈소스 프로젝트로 개발되었다.
- Jetty는 타 웹 애플리케이션 대비 적은 메모리를 사용하여 가볍고 빠르다.
- 애플리케이션에 내장 가능하다.
- 경량 웹 애플리케이션으로 소형 장비, 소규모 프로그램에 더 적합하다.

## Spring Boot 서버 Jetty로 변경하기

- 아무런 설정을 해주지 않았다면 Spring Boot의 기본 내장 서버인 Tomcat으로 실행된다.
- `build.gradle` 파일에서 `spring-boot-starter-web` 의존성이 추가되어있는 부분을 확인한다.
- 이 의존성 모듈 내에 포함되어 있는 Tomcat을 제외시킨다. 제외 시킨 후 프로젝트를 재 빌드하면 의존성이 제거되었음을 확인할 수 있다.

```groovy
implementation ('org.springframework.boot:spring-boot-starter-web') {
		exclude module : 'spring-boot-starter-tomcat'
	}
```

- Tomcat을 대체할 서버로 Jetty 의존성을 추가한다. 프로젝트를 빌드하면 Jetty에 대한 의존성이 추가되었음을 확인할 수 있다.

```groovy
implementation ('org.springframework.boot:spring-boot-starter-jetty')
```

- Spring Boot을 실행하면 Jetty를 통해 실행된다는걸 확인할 수 있다.

```bash
2022-12-09 13:55:09.900  INFO 44076 --- [           main] o.s.b.w.e.j.JettyServletWebServerFactory : Server initialized with port: 8080
```

- 서버의 종류는 Tomcat, Jetty를 제외하고도 Netty, Undertow 등 다양하다. 다른 서버 역시 변경하고 싶다면 Tomcat 의존성을 제외하고, 원하는 서버의 의존성을 추가하여 연결할 수 있다.