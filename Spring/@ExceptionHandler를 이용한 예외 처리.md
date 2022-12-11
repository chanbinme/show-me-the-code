# @ExceptionHandler를 이용한 예외 처리

- Spring이 처리하는 에러 응답 메시지를 직접 처리해보자

### MemberController

- `@ExceptionHandler` 추가

```java
package hobin.toyBoard.member.controller;

import hobin.toyBoard.member.dto.MemberDto;
import hobin.toyBoard.member.entity.Member;
import hobin.toyBoard.member.mapper.MemberMapper;
import hobin.toyBoard.member.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import javax.validation.constraints.Positive;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
@RequestMapping("/members")
@Slf4j
public class MemberController {

    ...
		...

    @ExceptionHandler
    public ResponseEntity handleException(MethodArgumentNotValidException e) {
        // (1)
        final List<FieldError> fieldErrors = e.getBindingResult().getFieldErrors();

        // (2)
        List<ErrorResponse.FieldError> errors =
                fieldErrors.stream()
                            .map(error -> new ErrorResponse.FieldError(
                                error.getField(),
                                error.getRejectedValue(),
                                error.getDefaultMessage()))
                            .collect(Collectors.toList());

        return new ResponseEntity<>(new ErrorResponse(errors), HttpStatus.BAD_REQUEST);
    }
}
```

- 클라이언트 쪽에서 회원 등록을 위해 `MemberController`의 `postMember()` 핸들러 메서드에 요청을 전송
- `RequestBody`에 유효하지 않은 요청 데이터가 포함되어 있어 유효성 검증에 실패하고, `MethodArgumentNotValidException`이 발생
- `MemberController`에는 `@ExceptionHandler` 애너테이션이 추가된 예외 처리 메서드인 `handleException()`이 있기 때문에 유효성 검증 과정에서 내부적으로 던져진 `MethodArgumentNotValidException` 을 `handleException()` 메서드가 전달 받는다.
- `MethodArgumentNotValidException`객체에서 `getBindingResult().getFieldErrors()`를 통해 발생한 에러 정보를 확인할 수 있다.
- 얻은 에러 정보를 `ResponseEntity`를 통해 Response Body로 전달한다.
- 필요한 정보들만 선택적으로 골라서 `ErrorResponse.FieldError`클래스에 담아서 List로 변환 후, `List<ErrorResponse.FieldError>`를 `ResponseEntity`클래스에 실어서 전달하고 있다.

### MemberDto.Post

```java
package hobin.toyBoard.member.dto;

import hobin.toyBoard.member.entity.Address;
import hobin.toyBoard.member.entity.Member;
import lombok.*;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;

public class MemberDto {

    @Getter
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    public static class Post {
        @NotBlank(message = "아이디를 입력해주세요.")
        private String name;

        @NotBlank(message = "이메일을 입력해주세요.")
        @Pattern(regexp = "^(?:\\w+\\.?)*\\w+@(?:\\w+\\.)+\\w+$", message = "이메일 형식이 올바르지 않습니다.")
        private String email;

        @NotBlank(message = "비밀번호를 입력해주세요.")
        @Pattern(regexp = "(?=.*[0-9])(?=.*[a-zA-Z])(?=.*\\W)(?=\\S+$).{8,16}", message = "비밀번호는 8~16자 영문 대 소문자, 숫자, 특수문자를 사용하세요.")
        private String password;

        @NotBlank(message = "닉네임을 입력해주세요.")
        @Pattern(regexp = "^[ㄱ-ㅎ가-힣a-z0-9-_]{2,10}$", message = "닉네임은 특수문자를 제외한 2~10자리여야 합니다.")
        private String nickname;

        @NotBlank(message = "주소를 입력해주세요.")
        private String city;

        @NotBlank(message = "주소를 입력해주세요.")
        private String street;

        @NotBlank(message = "주소를 입력해주세요.")
        private String zipcode;
    }
    ...
		...
}
```

### ErrorResponse

- 필요한 정보만 주도록 해주는 클래스

```java
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class ErrorResponse {
    // (1)
    private List<FieldError> fieldErrors;

    @Getter
    @AllArgsConstructor
    public static class FieldError {
        private String field;
        private Object rejectedValue;
        private String reason;
```

- 배열인 이유를 생각해보면 여러분들이 DTO 클래스에서 검증해야 되는 멤버 변수에서 유효성 검증에 실패하는 멤버 변수들이 하나 이상이 될 수 있기 때문에 유효성 검증 실패 에러 역시 하나 이상이 될 수 있다.

### Post Request Body

```java
{
    "name":"김찬빈",
    "email":"잘못된 이메일 형식",
    "password":"Honggildong1234!",
    "nickname":"개발하는콩",
    "city":"서울시 강북구",
    "street":"수유동 111-1",
    "zipcode":"22222"
}
```

### Post Response Body

```java
{
	"fieldErrors":
    {
        "field": "email",
        "rejectedValue": "잘못된 이메일 형식",
				"reason": "이메일 형식이 올바르지 않습니다."
    }
```

- 에러 메시지를 구체적으로 전송해주기 때문에 클라이언트 입장에서는 이제 어느 곳에 문제가 있는지를 구체적으로 알 수 있다.

## `@ExceptionHandler의 단점`

1. 각각의 Controller 클래스에서 `@ExceptionHandler` 애너테이션을 사용하여 Request Body에 대한 유효성 검증 실패에 대한 에러 처리를 해야되므로 **각 Controller 클래스마다 코드 중복이 발생한**다.
2. Controller에서 처리해야 되는 예외(Exception)가 유효성 검증 실패에 대한 예외(`MethodArgumentNotValidException`)만 있는것이 아니기 때문에 **하나의 Controller 클래스 내에서 `@ExceptionHandler`를 추가한 에러 처리 핸들러 메서드가 늘어난다.** 
3. 다양한 유형의 예외를 처리하기에는 적절하지 않다.