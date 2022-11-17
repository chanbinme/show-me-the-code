# Spring Boot, MySql, JPA 연동

## Dependency 추가

✔️build.gradle

```groovy
plugins {
	id 'org.springframework.boot' version '2.7.1'
	id 'io.spring.dependency-management' version '1.0.11.RELEASE'
	id "org.asciidoctor.jvm.convert" version "3.3.2"
	id 'java'
}

group = 'com.codestates'
version = '0.0.1-SNAPSHOT'
sourceCompatibility = '11'

repositories {
	mavenCentral()
}

ext {
	set('snippetsDir', file("build/generated-snippets"))
}

configurations {
	asciidoctorExtensions
}

dependencies {
	testImplementation 'org.springframework.restdocs:spring-restdocs-mockmvc'
	asciidoctorExtensions 'org.springframework.restdocs:spring-restdocs-asciidoctor'

	implementation 'mysql:mysql-connector-java' // mySql 의존성 추가
	implementation 'org.springframework.boot:spring-boot-starter-data-jpa' // JPA 의존성 추가
	implementation 'org.springframework.boot:spring-boot-starter-validation'
	implementation 'org.springframework.boot:spring-boot-starter-web'
	compileOnly 'org.projectlombok:lombok'
	runtimeOnly 'com.h2database:h2'
	annotationProcessor 'org.projectlombok:lombok'
	testImplementation 'org.springframework.boot:spring-boot-starter-test'
	implementation 'org.mapstruct:mapstruct:1.5.1.Final'
	annotationProcessor 'org.mapstruct:mapstruct-processor:1.5.1.Final'
	implementation 'org.springframework.boot:spring-boot-starter-mail'

	implementation 'com.google.code.gson:gson'
}

tasks.named('test') {
	outputs.dir snippetsDir
	useJUnitPlatform()
}

tasks.named('asciidoctor') {
	configurations "asciidoctorExtensions"
	inputs.dir snippetsDir
	dependsOn test
}

task copyDocument(type: Copy) {
	dependsOn asciidoctor
	println "asciidoctor output: ${asciidoctor.outputDir}"
	from file("${asciidoctor.outputDir}")
	into file("src/main/resources/static/docs")
}

build {
	dependsOn copyDocument
}

bootJar {
	dependsOn copyDocument
	from ("${asciidoctor.outputDir}") {
		into 'static/docs'
	}
}
```

## application.yml 또는 [application.properties](http://application.properties) 변경

✔️ application.yml

```yaml
spring:
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/{스키마 이름}?createDatabaseIfNotExist=true&serverTimezone=Asia/Seoul
    username: root
    password: *********
  jpa:
    database: mysql   # 추가 해준 부분
    database-platform: org.hibernate.dialect.MySQL5InnoDBDialect # MySql SQL을 처리해줄 수 있는 dialect 지정
    hibernate:
      ddl-auto: create-drop  # 시작과 종료 시 테이블 drop
    show-sql: true      # SQL 쿼리 출력
    properties:
      hibernate:
        format_sql: true  # SQL pretty print
```

- `createDatabaseIfNotExist=true` : 해당 데이터베이스가 존재하지 않으면 자동으로 데이터베이스를 생성한다.
- 실제 서비스 배포시에는 `create`, `create-drop` , `update`은 사용하지 않는다! 하지만 개발 초기 테스트시에는 유용하게 상요할 수 있다.

## DB 확인

- mysql 접속

```groovy
$ mysql -u root -p
```

- DB 확인

```groovy
$ show databases;
```

- DB 선택

```groovy
$ use [스키마 이름]
```

- 테이블 확인

```groovy
$ show tables;
```

![Untitled](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/9df7f35a-c431-47d1-8360-cf7d8190c18b/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221117%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221117T121830Z&X-Amz-Expires=86400&X-Amz-Signature=283f68e15d899fe3a3a0e12b780eae55ff8f854fed4858136efbb4b714989cc7&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject)