# Spring Data JPA에서 Auditing으로 생성일, 수정일 자동화하기

## `@EnableJpaAuditing` 추가

```java
@EnableJpaAuditing
@SpringBootApplication
public class TodoApplication {

	public static void main(String[] args) {
		SpringApplication.run(TodoApplication.class, args);
	}

}
```

- Spring Boot을 실행시키는 최상단 클래스에 추가해주자

## Auditing 기능을 담당할 엔티티 생성

```java
package toyproject.todo.audit;

import lombok.Getter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.Column;
import javax.persistence.EntityListeners;
import javax.persistence.MappedSuperclass;
import java.time.LocalDateTime;

@EntityListeners(AuditingEntityListener.class)
@MappedSuperclass
@Getter
public class Auditable {
    @CreatedDate  
    @Column(updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(updatable = false)
    private LocalDateTime lastModifiedAt;
}
```

- `@EntityListeners(AuditingEntityListner.class)` :  엔티티를 DB에 저장하기 전후에 커스텀 콜백을 요청할 수 있는 어노테이션. 여기서는 AuditingEntityListner.class를 인자로 넘기게 된다.
- `@MappedSuperClass` : 엔티티의 공통 매핑 정보가 필요할 때 주로 사용한다. 즉, 부모 클래스(엔티티)에 필드를 선언하고 단순히 속성만 받아서 사용하고싶을 때 사용하는 방법이다.
- `@Column(updatable = false)` : 개발자에 의해서 수정되지 않도록 설정.
- `@CreatedDate` : 엔티티가 생성된 날짜와 시간을 자동으로 삽입해주는 애너테이션
- `@LastModifiedDate` : 엔티티가 수정될 때, 수정된 시간과 날짜를 자동으로 삽입해주는 애너테이션

## Auditing을 사용할 엔티티에 상속

```java
package toyproject.todo.todo.entity;

import lombok.*;
import toyproject.todo.audit.Auditable;

import javax.persistence.*;

@Entity
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Todo extends Auditable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) // 확인 필요
    private Long todoId;

    @Column(length = 30)
    private String title;

    @Column(name = "orders")
    private Long order = 0L;

    private boolean completed = false;
}
```

## Test를 해보자

```java
@DataJpaTest
class TodoRepositoryTest {

    @Autowired
    private TodoRepository todoRepository;

    @Test
    public void saveTodoTest() throws Exception {
        // given
        Todo todo = Todo.builder()
                .order(1L)
                .title("양치하기")
                .completed(false)
                .build();

        // when
        Todo saveTodo = todoRepository.save(todo);

        // then
        assertNotNull(saveTodo);
        assertNotNull(todo.getCreatedAt());
        assertNotNull(todo.getLastModifiedAt());
        assertEquals(todo.getTodoId(), saveTodo.getTodoId());
        assertEquals(todo.getTitle(), saveTodo.getTitle());
        assertEquals(todo.getOrder(), saveTodo.getOrder());
        assertEquals(todo.isCompleted(), saveTodo.isCompleted());
    }
}
```

![스크린샷 2022-12-01 오후 11.58.59.png](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FblCZ6F%2FbtrSz8zebYx%2F0LLR6rceZScgIKNk9pcem1%2Fimg.png)

![스크린샷 2022-12-01 오후 11.59.29.png](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FbA6L1n%2FbtrSCLpvcqt%2FI3TKMazy74xlRJJXYTfq21%2Fimg.png)

![Untitled](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2Fbi8hny%2FbtrSE6GcHDd%2FxyGQonU98rNMOmZx46mYnK%2Fimg.png)

## 참조

[https://wonit.tistory.com/484](https://wonit.tistory.com/484)