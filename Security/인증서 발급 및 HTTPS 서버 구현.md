# 인증서 발급 및 HTTPS 서버 구현

- 자바는 두 가지의 인증서 형식을 지원한다.
    1. PKCS12(Public Key Cryptographic Standards #12) :  여러 인증서와 키를 포함할 수 있으며, 암호로 보호된 형식. 업계에서 많이 사용된다.
    2. JKS(Java KeyStore : PKCS12와 유사하다. 독점 형식이며 Java 환경으로 제한된다.

## 설치

- mkcert라는 프로그램을 이용해서 로컬 환경(내 컴퓨터)에서 신뢰할 수 있는 인증서를 만들 수 있다. mkcert는 PKCS12 현식만 지원한다.

### macOS

1. 명령어를 통해 로컬을 인증된 발급기관으로 추가

```java
$ mkcert -install
```

1. 아래 명령어를 통해 PKCS12 인증서를 생성

```java
$ mkcert -pkcs12 localhost
```

## HTTPS 서버 작성

- Spring Boot를 이용하면 HTTPS 서버를 간단하게 작성할 수 있다.
1. 생성된 인증서(localhost.p12)를 resource 폴더로 이동시킨다.
2. application.properties에서 관련 설정을 추가한다.

```java
server.ssl.key-store=classpath:localhost.p12  #  -> 인증서 경로
server.ssl.key-store-type=PKCS12              #  -> 인증서 형식
server.ssl.key-store-password=changeit        #  -> 인증서 비밀번호

# 여기서 비밀번호인 changeit은 비밀번호를 설정하지 않았을 때의 기본값이다.
# 인증서 비밀번호는 인증서를 생성할 때 설정하거나 생성 후 변경해줄 수 있다.
```

1. 서버 실행

![Untitled](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/fa2617c0-c701-48d3-b909-7ce545a6d1d8/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221117%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221117T122102Z&X-Amz-Expires=86400&X-Amz-Signature=c42047a02ecd4f9353d5d797eba8f52b7328c441d16ed6c06c048af42f61885f&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject)