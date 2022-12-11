# 사용자 정의 예외(Custom Exception)

### 예외 코드 정의

```java
package hobin.toyBoard.exception;

import lombok.Getter;

public enum ExceptionCode {
    MEMBER_NOT_FOUND(404, "회원을 찾을 수 없습니다."),
    MEMBER_EXISTS(409, "이미 존재하는 회원입니다.");
    @Getter
    private int status;

    @Getter
    private String message;

    ExceptionCode(int status, String message) {
        this.status = status;
        this.message = message;
    }
}
```

- ExceptionCode를 enum으로 정의하면 비즈니스 로직에서 발생하는 다양한 유형의 예외를 enum에 추가해서 사용할 수 있다.

### BusinessLogicException 구현

```java
package hobin.toyBoard.exception;

import lombok.Getter;

public class BussinessLogicException extends RuntimeException {
    @Getter
    private ExceptionCode exceptionCode;

    public BussinessLogicException(ExceptionCode exceptionCode) {
        super(exceptionCode.getMessage());
        this.exceptionCode = exceptionCode;
    }
}
```

- `BusinessLogicException`은 `RuntimeException`을 상속하고 있으며 `ExceptionCode`를 멤버 변수로 지정하여 생성자를 통해서 조금 더 구체적인 예외 정보들을 제공해줄 수 있다.
- 상위 클래스인 `RuntimeException` 의 생성자(super)로 예외 메시지를 전달해준다.
- `BusinessLogicException` 은 서비스 계층에서 개발자가 의도적으로 예외를 던져야 하는 다양한 상황에서 ExceptionCode 정보만 바꿔가며 던질 수 있다.

### MemberService에 BusinessLogicException 적용

```java
package hobin.toyBoard.member.service;

import hobin.toyBoard.exception.BussinessLogicException;
import hobin.toyBoard.exception.ExceptionCode;
import hobin.toyBoard.member.entity.Member;
import hobin.toyBoard.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
//@Transactional(readOnly = true)
public class MemberService {
    ...
		...

    public void verifyExistMember(String email) {
        Optional<Member> optionalMember = memberRepository.findByEmail(email);
        if (optionalMember.isPresent()) {
            throw new BussinessLogicException(ExceptionCode.MEMBER_EXISTS);
        }
    }

    public Member findVerifiedMember(Long memberId) {
        return memberRepository.findById(memberId)
                .orElseThrow(() -> new BussinessLogicException(ExceptionCode.MEMBER_NOT_FOUND));
    }
}
```

### Exception Advice에서 BusinessLogicException 처리

```java
package hobin.toyBoard.advice;

import hobin.toyBoard.exception.BussinessLogicException;
import hobin.toyBoard.exception.ExceptionCode;
import hobin.toyBoard.response.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.validation.ConstraintViolationException;

/**
 * 클래스에 @RestControllerAdvice 애너테이션을 추가하면
 * Controller 클래스에서 발생하는 예외를 도맡아 처리한다.
 * 그리고 예외 처리를 공통화 할 수 있다.
 */
@RestControllerAdvice
public class GlobalExceptionAdvice {

    ...
		...

    @ExceptionHandler
    public ResponseEntity handleBusinessLogicException(BussinessLogicException e) {
        final ErrorResponse response = ErrorResponse.of(e.getExceptionCode());
        return new ResponseEntity<>(response, HttpStatus.valueOf(e.getExceptionCode().getStatus()));
    }
}
```

### ErrorResponse 수정

```java
package hobin.toyBoard.response;

import hobin.toyBoard.exception.BussinessLogicException;
import hobin.toyBoard.exception.ExceptionCode;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.data.crossstore.ChangeSetPersister;
import org.springframework.http.HttpStatus;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;

import javax.validation.ConstraintViolation;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
public class ErrorResponse {

		...
		...
    private int status;
    private String message;
   

    private ErrorResponse(int status, String message) {
        this.status = status;
        this.message = message;
    }

    public static ErrorResponse of(ExceptionCode exceptionCode) {
        return new ErrorResponse(exceptionCode.getStatus(), exceptionCode.getMessage());
    }
		
		...
		...
    }
}
```

- `@ResponseStatus`애너테이션은 고정된 HttpStatus를 지정하기 때문에 `BusinessLogicException`과 같이 다양한 Status를 동적으로 처리할 수 없으므로 `ResponseEntity`를 사용해서 HttpStatus를 동적으로 지정하도록 변경

> @RestControllerAdvice에서 `@ResponseStatus` 를 쓸까? `ResponseEntity` 를 쓸까?
> 
> 
> 한가지 유형으로 고정된 예외를 처리할 경우에는 `@ResponseStatus` 로 HttpStatus를 지정해서 사용하면 되고, `BusinessLogicException` 처럼 다양한 유형의 Custom Exception을 처리하고자 할 경우에는 `ResponseEntity` 를 사용하면 된다.
> 

### Postman으로 존재하지 않는 회원 조회 시

```java
{
    "status": 404,
    "message": "회원을 찾을 수 없습니다.",
    "fieldErrors": null,
    "violationErrors": null
}
```