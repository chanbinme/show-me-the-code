# Spring WebFlux 적용

- 기타 구체적인 예외 처리에 대한 구현은 적용하지 않았다.

## 프로젝트 설정

### build.gradle 설정

```groovy
...
...

dependencies {
	implementation 'org.springframework.boot:spring-boot-starter-webflux'     // (1)
	implementation 'org.springframework.boot:spring-boot-starter-validation'
	implementation 'org.springframework.boot:spring-boot-starter-data-r2dbc'   // (2)
	compileOnly 'org.projectlombok:lombok'
	annotationProcessor 'org.projectlombok:lombok'
	testImplementation 'org.springframework.boot:spring-boot-starter-test'
	testImplementation 'io.projectreactor:reactor-test'
	implementation 'org.mapstruct:mapstruct:1.5.1.Final'
	annotationProcessor 'org.mapstruct:mapstruct-processor:1.5.1.Final'
	runtimeOnly 'io.r2dbc:r2dbc-h2'  // (3)
}

...
...
```

- `spring-boot-starter-web` → `spring-boot-starter-webflux` 변경
- `spring-boot-starter-data-jpa` → `spring-boot-starter-data-r2dbc` 변경 : 리액티브 스택에서는 JPA 대신 R2DBC를 사용
- `com.h2database:h2` → `io.r2dbc:r2dbc-h2` 변경 : 인메모리 DB인 H2에서 Non-Blocking을 지원하는 드라이버를 사용할수 있도록 변경

### application.yml 설정

```yaml
spring:
  sql:
    init:
      schema-locations: classpath*:db/h2/schema.sql   // (1)
      data-locations: classpath*:db/h2/data.sql       // (2)
logging:
  level:
    org:
      springframework:
        r2dbc: DEBUG          // (3)
```

- (1), (2) 직접 테이블 스키마를 정의하고, 샘플 데이터를 정의해서 애플리케이션 실행 시, SQL 스크립트를 실행할 수 있다.
- Spring Data R2DBC는 Spring Data JPA의 Auto DDL 같은 기능을 제공하지 않기 때문에 (1)과 같이 직접 SQL 스크립트 설정을 추가해줘야 한다.
- (3) Spring Data R2DBC 기술을 이용해 데이터베이스와 상호작용하는 동작을 로그로 출력하고자 r2dbc 로그 레벨을 DEBUG로 설정

## DB Schema 설정

```scheme
CREATE TABLE IF NOT EXISTS MEMBER (
    MEMBER_ID bigint NOT NULL AUTO_INCREMENT,
    EMAIL varchar(100) NOT NULL UNIQUE,
    NAME varchar(100) NOT NULL,
    PHONE varchar(100) NOT NULL,
    MEMBER_STATUS varchar(20) NOT NULL,
    CREATED_AT datetime NOT NULL,
    LAST_MODIFIED_AT datetime NOT NULL,
    PRIMARY KEY (MEMBER_ID)
);

CREATE TABLE IF NOT EXISTS STAMP (
    STAMP_ID bigint NOT NULL AUTO_INCREMENT,
    STAMP_COUNT bigint NOT NULL,
    MEMBER_ID bigint NOT NULL,
    CREATED_AT datetime NOT NULL,
    LAST_MODIFIED_AT datetime NOT NULL,
    PRIMARY KEY (STAMP_ID),
    FOREIGN KEY (MEMBER_ID) REFERENCES MEMBER(MEMBER_ID)
);

...
...
```

- `src/main/resources/db/h2` 에 있는 schema.sql 파일의 테이블 생성 스크립트
- schema.sql 파일은 테이블 schema 설정에 사용된다.

## 애플리케이션 공통 설정

```java
package com.codestates;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@EnableR2dbcAudifing
@EnableR2DdbRepositories
@SpringBootApplication
public class SpringMvcOutboundSampleApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringMvcOutboundSampleApplication.class, args);
	}

}
```

- R2DBC의 Repository를 사용하기 위해서는 main() 메서드가 포함된 애플리케이션 클래스에 `@EnableR2dbcRepoistories` 애너테이션을 추가해주어야 한다.
- 데이터베이스에 엔티티가 저장 및 수정될 때, 생성 날짜와 수정 날짜를 자동으로 저장할 수 있도록 Autditing 기능을 사용하기 위해 `@EnableR2dbcAuditing` 애너테이션을 추가한다.

## Controller 구현

```java
package com.codestates.member.controller;

import com.codestates.member.dto.MemberDto;
import com.codestates.member.mapper.MemberMapper;
import com.codestates.member.service.MemberService;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import javax.validation.Valid;
import javax.validation.constraints.Positive;
import java.util.List;

@Validated
@RestController
@RequestMapping("/v12/members")
public class MemberController {
    private final MemberService memberService;
    private final MemberMapper mapper;

    public MemberController(MemberService memberService, MemberMapper mapper) {
        this.memberService = memberService;
        this.mapper = mapper;
    }

    @PostMapping
    public ResponseEntity postMember(@Valid @RequestBody Mono<MemberDto.Post> requestBody) {  // (1)
        Mono<MemberDto.Response> result =
                requestBody
                        .flatMap(post -> memberService.createMember(mapper.memberPostToMember(post))) // (2)
                        .map(member -> mapper.memberToMemberResponse(member));

        return new ResponseEntity<>(result, HttpStatus.CREATED);
    }

    @PatchMapping("/{member-id}")
    public ResponseEntity patchMember(@PathVariable("member-id") @Positive long memberId,
                                      @Valid @RequestBody Mono<MemberDto.Patch> requestBody) {    // (3)
        Mono<MemberDto.Response> response =
                requestBody
                        .flatMap(patch -> {            // (4)
                            patch.setMemberId(memberId);         
                            return memberService.updateMember(mapper.memberPatchToMember(patch));
                        })
                        .map(member -> mapper.memberToMemberResponse(member));

        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @GetMapping("/{member-id}")
    public ResponseEntity getMember(@PathVariable("member-id") @Positive long memberId) {
        Mono<MemberDto.Response> response =
                memberService.findMember(memberId)   // (5)
                        .map(member -> mapper.memberToMemberResponse(member));
        return new ResponseEntity(response, HttpStatus.OK);
    }

    @GetMapping
    public ResponseEntity getMembers(@RequestParam("page") @Positive int page,
                                     @RequestParam("size") @Positive int size) {
        Mono<List<MemberDto.Response>> response =
                memberService.findMembers(PageRequest.of(page - 1, size, Sort.by("memberId").descending()))  // (6)
                        .map(pageMember -> mapper.membersToMemberResponses(pageMember.getContent()));

        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @DeleteMapping("/{member-id}")
    public ResponseEntity deleteMember(@PathVariable("member-id") long memberId) {
        Mono<Void> result = memberService.deleteMember(memberId);    // (7)
        return new ResponseEntity(result, HttpStatus.NO_CONTENT);
    }
}
```

- (1)을 보면 postMember() 핸들러 메서드의 파라미터인 MemberDto.Post 객체가 Mono로 래핑되어 있습니다.

  이처럼 Spring WebFlux에서는 request body로 단순히 MemberDto.Post 객체를 전달 받을 수도 있지만 (1)과 같이 `Mono<MemberDto.Post>`와 같이 전달 받을 수도 있습니다.

  ⭐ 이렇게 Mono로 래핑해서 전달 받으면 어떤 장점이 있을까요?

  전달 받은 객체에 **Blocking 요소가 포함되지 않도록 request body를 전달 받는 순간부터 Non-Blocking으로 동작하도록 Operator 체인을 바로 연결해서 다음 처리를 시작할 수 있습니다.**

- (1)에서 전달 받은 request body가 `Mono<MemberDto.Post>`이기 때문에 (2)와 같이 바로 다음 처리를 Non-Blocking으로 처리할 수 있도록 Operator 체인을 연결할 수 있습니다.

  (2)에서는 MemberService 클래스의 createMember() 메서드를 호출해서 회원 정보를 저장하는 처리를 바로 이어서 수행하고 있습니다.

  모든 처리가 **Mono Sequence내에서 처리 되기 때문에 Non-Blocking으로 처리 됩니다.**

- (3)에서도 역시 `Mono<MemberDto.Patch>`로 request body를 전달 받습니다.
- (4)에서 Mono Sequence 내부에서 MemberService 클래스의 updateMember() 메서드를 호출해서 회원 정보를 저장하는 처리를 바로 이어서 수행하고 있습니다.
- (5)에서는 MemberService 클래스의 findeMember() 메서드를 호출해서 회원 정보를 조회하고 있습니다.

  한가지 기억해야 될 내용은 MemebrService 클래스의 메서드를 호출해서 **Mono Sequecne를 추가적으로 연결할 수 있다라는 의미는 MemberService 클래스의 메서드 역시 리턴 타입이 Mono라는 것**입니다.

  즉, 우리가 기존에 알고 있던 MemberService 클래스의 메서드는 대부분 Member 객체를 리턴했지만 **⭐ Spring WebFlux 기반의 MemberService 클래스는 Mono와 같이 Mono로 래핑한 값을 리턴**한다는 사실을 꼭 기억하기 바랍니다.

- (6)에서는 페이지네이션을 위해 PageRequest 객체를 MemberController 쪽에서 직접 만들어서 MemberService 쪽으로 전달하고 있는 것이 Spring MVC 방식과 조금 다른 점입니다.

  Spring MVC 방식에서는 단순히 page, size 정보만 MemberService 쪽으로 전달했던 것을 떠올려 보기 바랍니다.

- (7)에서는 회원 정보를 삭제하기 위해 MemberService의 deleteMember() 메서드를 호출합니다.
  리턴 되는 데이터가 없는 경우, Spring MVC 방식에서는 메서드이 리턴 타입이 `void`이지만 Spring WebFlux에서는 `Mono<Void>`가 됩니다.

Spring WebFlux에서의 핸들러 메서드는 코드 4-41과 같이 응답을 전송하기 위해 ResponseEntity를 사용하지만 ⭐ **ResponseEntity에 넘겨주는 응답 데이터가 단순한 객체가 아닌 Mono로 래핑된 객체라는 사실**을 기억해야합니다.

⭐ Spring WebFlux에서는 모든 데이터가 Mono나 Flux로 래핑되어 전달된다는 것을 반드시 기억하세요!

## Entity 클래스 정의

```java
package com.codestates.member.entity;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;
import java.time.LocalDateTime;

@NoArgsConstructor
@Getter
@Setter
@Table    // (1)
public class Member {
    @Id   // (2)
    private Long memberId;

    private String email;

    private String name;

    private String phone;

    private MemberStatus memberStatus = MemberStatus.MEMBER_ACTIVE;

    @CreatedDate   // (3)
    private LocalDateTime createdAt;

    @LastModifiedDate   // (4)
    @Column("last_modified_at")
    private LocalDateTime modifiedAt;

    public Member(String email) {
        this.email = email;
    }

    public Member(String email, String name, String phone) {
        this.email = email;
        this.name = name;
        this.phone = phone;
    }
    public enum MemberStatus {
        MEMBER_ACTIVE("활동중"),
        MEMBER_SLEEP("휴면 상태"),
        MEMBER_QUIT("탈퇴 상태");

        @Getter
        private String status;

        MemberStatus(String status) {
           this.status = status;
        }
    }
}
```

- R2DBC는 Spring Data JDBC나 Spring Data JPA처럼 애너테이션이나 컬렉션 등을 이용한 연관 관계 매핑은 지원하지 않는다.
- (1) `@Table` 애너테이션을 명시적으로 추가했지만 생략해도 무방하다.
- (2) Spring Data 패밀리 프로젝트의 기술들은 식별자에 해당되는 필드에 `@Id` 애너테이션을 필수로 추가해야 한다.
- (3), (4) `@CreatedDate`, `@LastModifiedDate`
  애너테이션을 추가해서 데이터가 저장 또는 업데이트 될 때 별도의 날짜/시간 정보를 추가하지 않아도 Spring Data 패밀리에서 지원하는 Auditing 기능을 통해 자동으로 날짜/시간 정보가 테이블에 저장되도록 했다.

```java
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;

@NoArgsConstructor
@Getter
@Setter
@Table
public class Stamp {
    @Id
    private long stampId;
    private int stampCount;
    private long memberId;    // (1)

    @CreatedDate
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column("last_modified_at")
    private LocalDateTime modifiedAt;

    public Stamp(long memberId) {
        this.memberId = memberId;
    }
}
```

- Stamp 클래스가 Member와 1대1 관계이므로 (1)과 같이 MEMBER 테이블의 식별자에 해당하는 memberId 필드가 외래키 역할을 하도록 추가했다.
- Spring R2DBC에서 연관 관계 매핑을 지원하지 않는 이유는 연관 관계 매핑이 적용되는 순간 내부적으로 Blocking 요소가 포함될 가능성이 있기 때문이다.
- Spring WebFlux의 기술을 효과적으로 잘 활용하기 위해서는 구현 코드 또는 사용하는 써드 파티 라이브러리 등에 Blocking 요소가 포함이 되는지 여부를 잘 판단하는 것도 굉장히 중요하다.

## 서비스 클래스 구현

```java
import com.codestates.exception.BusinessLogicException;
import com.codestates.exception.ExceptionCode;
import com.codestates.member.entity.Member;
import com.codestates.member.repository.MemberRepository;
import com.codestates.stamp.Stamp;
import com.codestates.utils.CustomBeanUtils;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;

import static org.springframework.data.relational.core.query.Criteria.where;
import static org.springframework.data.relational.core.query.Query.query;

@Transactional
@Service
public class MemberService {
    private final MemberRepository memberRepository;  // (1)
    private final CustomBeanUtils<Member> beanUtils;
    private final R2dbcEntityTemplate template;       // (2)
    public MemberService(MemberRepository memberRepository, CustomBeanUtils<Member> beanUtils, R2dbcEntityTemplate template) {
        this.memberRepository = memberRepository;
        this.beanUtils = beanUtils;
        this.template = template;
    }

    public Mono<Member> createMember(Member member) {
        return verifyExistEmail(member.getEmail())      // (3)
                .then(memberRepository.save(member))    // (4)
                .map(resultMember -> {
                    // Stamp 저장
                    template.insert(new Stamp(resultMember.getMemberId())).subscribe();  // (5)

                    return resultMember;
                });

    }

    public Mono<Member> updateMember(Member member) {
        return findVerifiedMember(member.getMemberId())    // (6)
                .map(findMember -> beanUtils.copyNonNullProperties(member, findMember))  // (7)
                .flatMap(updatingMember -> memberRepository.save(updatingMember));    // (8)
    }

    @Transactional(readOnly = true)
    public Mono<Member> findMember(long memberId) {
        return findVerifiedMember(memberId);
    }

    @Transactional(readOnly = true)
    public Mono<Page<Member>> findMembers(PageRequest pageRequest) {
        return memberRepository.findAllBy(pageRequest)  // (9)
                .collectList()     // (10)
                .zipWith(memberRepository.count())   // (11)
                .map(tuple -> new PageImpl<>(tuple.getT1(), pageRequest, tuple.getT2()));  // (12)
    }

    public Mono<Void> deleteMember(long memberId) {
        return findVerifiedMember(memberId)
                .flatMap(member -> template.delete(query(where("MEMBER_ID").is(memberId)), Stamp.class))  // (13)
                .then(memberRepository.deleteById(memberId));              // (14)
    }

    private Mono<Void> verifyExistEmail(String email) {
        return memberRepository.findByEmail(email)
                .flatMap(findMember -> {
                    if (findMember != null) {
                        return Mono.error(new BusinessLogicException(ExceptionCode.MEMBER_EXISTS)); // (15)
                    }
                    return Mono.empty();    // (16)
                });
    }

    private Mono<Member> findVerifiedMember(long memberId) {
        return memberRepository
                .findById(memberId)
                .switchIfEmpty(Mono.error(new BusinessLogicException(ExceptionCode.MEMBER_NOT_FOUND))); // (17)
    }
}
```

- Spring WebFlux에서는 **모든 데이터가 Mono 또는 Flux의 Operator 체인 안에서 동작**한다.
- (2) Spring Data R2DBC에서 지원하는 **가독성 좋은 SQL 쿼리 빌드 메서드**를 이용하는 방식
- (4) `then()` Operator : 이 전에 동작하고 있던 Sequence를 종료하고 새로운 Sequence를 시작하게 해주는 Operator
- (16) Spring MVC의 경우 별도의 코드가 필요없지만 **Spring WebFlux의 경우 Mono 안에서 모든 처리가 이루어져야 하므로, Mono.empty()를 리턴해 주어야 다음 동작을 진행할 수 있다.**
- Spring MVC 기반 코드에서는 JPA를 CASCADE 기능을 이용해서 회원 정보를 저장하면 스탬프 정보까지 자동으로 테이블에 저장을 해주지만 Spring Data R2DBC의 경우, 직접 테이블에 저장하는 코드가 필요하다.

  (5)에서 **R2dbcEntityTemplate**의 `insert()` 메서드를 이용해서 스탬프 정보를 테이블에 저장하고 있다.

  여기서 중요한 포인트는 insert() 메서드를 호출하고, **subscribe()를 호출해야 된다는 것이**다.

  map() Operator에서 리턴하는 값은 Controller 쪽으로 전달하는 회원 정보다.

  스탬프 정보는 회원 정보를 저장하는 Operator 체인 내부에 별도로 존재하는 Inner Sequence이기 때문에 `subscribe()`를 호출해야지만 테이블에 데이터를 저장하는 동작을 수행한다.

- 리액티브 프로그래밍의 특징 중 하나는 `subscribe()` 메서드를 호출하지 않으면 아무 동작을 수행하지 않는다는 것이다.
- (17) `switchIfEmpty()` Operator를 사용하여 회원이 존재하지 않는 다면 Exception을 throw하고 있습니다.

  `switchIfEmpty()` Operator는 emit되는 데이터가 없다면 `switchIfEmpty()` Operator의 파라미터로 전달되는 Publisher가 **대체 동작을 수행할 수 있게 해주는 Operator이다.**

- (7)은 회원 정보 중에서 request body에 포함된 정보만 테이블에 업데이트 되도록 해주는 유틸리티 클래스이다.

  `beanUtils.copyNonNullProperties(member, findMember))`에서 첫 번째 파라미터는 request body에 포함된 데이터이며, 두 번째 파라미터는 테이블에서 조회한 회원의 기존 데이터다.

  첫 번째 파라미터(member)에서 null이 아닌 필드의 값만 두 번째 파라미터(findMember)의 동일한 필드에 덮어 씌우기 때문에 실제 테이블에 저장 전, 간편하게 회원 정보 필드를 업데이트 할 수 있다.

- (9) Spring MVC 기반 코드에서는 PageRequest 객체를 MemberService 클래스에서 생성했지만 여기서는 PageRequest 객체가 Sequence 내부에서 재사용 되어야하기 때문에 Controller 쪽에서 미리 생성한 PageRequest 객체를 findMembers() 메서드의 파라미터로 전달하고 있다.
- Spring MVC 기반 코드에서는 PageRequest 객체를 MemberService 클래스에서 생성했지만 여기서는 PageRequest 객체가 Sequence 내부에서 재사용 되어야하기 때문에 Controller 쪽에서 미리 생성한 PageRequest 객체를 findMembers() 메서드의 파라미터로 전달하고 있다.
- (13)에서는 **R2dbcEntityTemplate**의 ****`delete()` 메서드와 `SQL 쿼리 빌드 메서드 체인`을 통해 스탬프 정보를 삭제하고 있다.

  MEMBER 테이블과 STAMP 테이블은 외래키로 관계를 맺고 있기 때문에 MEMBER 테이블의 식별자를 외래키로 가지는 STAMP 테이블의 스탬프 정보를 먼저 삭제해 주어야 한다.

- (13)에서 스탬프 정보를 삭제했으니 (14)에서는 회원 정보를 삭제한다.
  여기서는 MemberRepository의 deleteById() 메서드를 이용해서 회원 정보를 삭제한다.

## Repository 구현

```java
import com.codestates.member.entity.Member;
import org.springframework.data.domain.Pageable;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface MemberRepository extends R2dbcRepository<Member, Long> {  // (1)
    Mono<Member> findByEmail(String email);    // (2)
    Flux<Member> findAllBy(Pageable pageable); // (3)
}
```

- (1)의 `R2dbcRepository` 인터페이스는 Spring Data R2DBC에서 사용하는 Repository입니다.

  `R2dbcRepository`는 기본적인 CRUD 기능과 페이지네이션, 정렬 기능을 모두 포함하고 있습니다.

- (2)와 (3)을 보면 Spring Data R2DBC에서 조회되는 데이터는 모두 Mono 또는 Flux임을 알 수 있습니다.

  이를 통해 Controller부터 Repository까지 완전한 Non-Blocking 동작을 수행할 수 있게됩니다.