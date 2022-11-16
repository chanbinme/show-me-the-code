# Spring Boot Profile 환경 설정하기(YAML)
> Spring profile을 통해 다양한 환경(local, server)을 application.yml에 설정할 수 있다.
> 

![Untitled](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/9d7da655-4a82-46f1-be0c-9da7e566e8fa/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221116%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221116T113119Z&X-Amz-Expires=86400&X-Amz-Signature=663053ff69e63dac621fe67c1e54d141e610beffe8cd9b72d7c2e27119473949&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject)

- `application.yml` 파일은 주로 애플리케이션의 실행 환경에 상관없이 공통적으로 적용할 수 있는 프로퍼티를 설정할 수 있다.
- `application-local.yml` , `application-server.yml` 을 다르게 설정하여 각 실행 환경에 맞게 적용할 수 있다.

✔️ `application-local.yml`

```yaml
# 로컬 환경에서 사용하는 정보들은 application-local.yml 파일에 설정합니다.
spring:
  h2:
    console:
      enabled: true
      path: /h2
  datasource:
    url: jdbc:h2:mem:test
  jpa:
    hibernate:
      ddl-auto: create  
    show-sql: true     
    properties:
      hibernate:
        format_sql: true  
  sql:
    init:
      data-locations: classpath*:db/h2/data.sql
logging:
  level:
    org:
      springframework:
        orm:
          jpa: DEBUG
server:
  servlet:
    encoding:
      force-response: true
```

✔️`application-server.yml`

```yaml
spring:
  profiles:
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/test?createDatabaseIfNotExist=true&serverTimezone=Asia/Seoul
    username: root
    password: *********
  jpa:
    database: mysql  
    database-platform: org.hibernate.dialect.MySQL5InnoDBDialect # MySql SQL을 처리해줄 수 있는 dialect 지정
    hibernate:
      ddl-auto: create-drop  
    show-sql: true     
    properties:
      hibernate:
        format_sql: true  
logging:
  level:
    org:
      hibernate: info
```

## Intellij에서 프로파일 적용

1. Run > Edit Configurations 선택
2. Spring Boot Application 선택
3. Program argments 필드에 `—Spring.profiles.active={profile 이름}` 입력
    
    ![스크린샷 2022-11-16 오후 3.48.46.png](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/592c267f-2cc1-46d3-bc6b-52c4286e24a3/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2022-11-16_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_3.48.46.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221116%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221116T113133Z&X-Amz-Expires=86400&X-Amz-Signature=09b856964569e6c085236309294563d5141e2e494c6670fdfbe15013f0d6ac9a&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA%25202022-11-16%2520%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE%25203.48.46.png%22&x-id=GetObject)
    

## Jar파일에 프로파일 적용

1. 프로젝트 파일 > build > libs

```yaml
$ cd build/libs
```

1. jar 파일 실행에 `--spring.profiles.active={profile 이름}` 설정 추가

```yaml
$ java -jar [jar 파일명].jar --spring.profiles.active=[profile 이름]
```

![스크린샷 2022-11-16 오후 4.22.21.png](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/906aecfd-b9a4-4702-8a81-20978e4263c4/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2022-11-16_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_4.22.21.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221116%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221116T113159Z&X-Amz-Expires=86400&X-Amz-Signature=5757f8f621b4eb645060836dad1ec8270a9fb2795c399b2553d23cf717c9448f&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA%25202022-11-16%2520%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE%25204.22.21.png%22&x-id=GetObject)

```yaml
[           main] .c.Section3Week3HomeworkBuildApplication : The following 1 profile is active: "server"
[           main] o.s.b.c.config.ConfigDataEnvironment     : Property 'spring.profiles' imported from location 'class path resource [application-server.yml]' is invalid and should be replaced with 'spring.config.activate.on-profile' [origin: class path resource [application-server.yml] - 4:12]
```

- `application-server.yml` 파일이 적용된 것을 확인할 수 있다.

## 참조

[Spring Boot & MySQL 연동하기](https://gyuwon95.tistory.com/167)