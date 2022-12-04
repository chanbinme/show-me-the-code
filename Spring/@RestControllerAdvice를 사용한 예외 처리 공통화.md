# @RestControllerAdvice를 사용한 예외 처리 공통화

## 예외 처리란?

- 프로그램 실행 시 발생할 수 있는 예외에 대비하는 것으로 프로그램이 비정상적으로 종료되는 것을 막고 실행 상태를 유지하는 것
- Spring에서의 예외는 애플리케이션에 문제가 발생할 경우, 이 문제를 알려서 처리하는 것 뿐만 아니라 유효성 검증에 실패했을 때와 같이 실패를 하나의 예외로 간주하여 이 예외를 던져서(throw) 예외 처리를 유도한다.

## @RestControllerAdvice

- `@RestControllerAdvice` 애너테이션을 추가한 클래스를 이용하면 **예외 처리를 공통화 할 수 있다.**
- `@RestControllerAdvice` 애너테이션을 추가한 클래스는 Controller 클래스에서 발생하는 예외를 도맡아서 처리하게 된다.
- `@RestControllerAdvice` 애너테이션을 사용하면 JSON 형식의 데이터를 Response Body로 전송하기 위해 ResponseEntity로 래핑할 필요가 없다.
- `@ResponseStatus` 애너테이션으로 HTTP Status를 대신 표현할 수 있다.
- 예외 처리 공통화를 구현해보자

## ExceptionAdvice 클래스 정의

- `RestControllerAdvice` 애너테이션을 추가해 여러개의 Controller 클래스에서 `@ExceptionHandler`, `@InitBinder` 또는 `@ModelAttribute`가 추가된 메서드를 공유해서 사용할 수 있다.

```java
package com.codestates.advice;

import com.codestates.exception.BusinessLogicException;
import com.codestates.response.ErrorResponse;
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

    @ExceptionHandler
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorResponse handleMethodArgumentNotValidException(
            MethodArgumentNotValidException e) {
        final ErrorResponse response = ErrorResponse.of(e.getBindingResult());

        return response;
    }

    @ExceptionHandler
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorResponse handleConstraintViolationException(ConstraintViolationException e) {
        final ErrorResponse response = ErrorResponse.of(e.getConstraintViolations());
        
				return response;
    }
```

## ErrorResponse 클래스 정의

- `ErrorResponse` 클래스를 이용해서 에러 정보만 담아서 클라이언트에게 응답으로 전송

```java
package com.codestates.response;

import lombok.Getter;
import org.springframework.validation.BindingResult;

import javax.validation.ConstraintViolation;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
public class ErrorResponse {

    // MethodArgumentNotValidException으로부터 발생하는 에러 정보를 담는 멤버 변수
    private List<FieldError> fieldErrors;

    // ConstraintViolationExceiption으로부터 발생하는 에러 정보를 담는 멤버 변수
    private List<ConstraintViolationError> violationErrors;

    /**
     * ErrorResponse 클래스의 생성자
     * private 접근 제한자를 지정함으로써 new연산자로 ErrorResponse 객체를 생성할 수 없다.
     * 대신 of() 메서드를 이용해 ErrorResponse의 객체를 생성할 수 있다.
     * 덕분에 ErrorResponse의 객체를 생성함과 동시에 ErrorResponse의 역할을 명확하게 해준다.
     */
    private ErrorResponse(List<FieldError> fieldErrors, List<ConstraintViolationError> violationErrors) {
        this.fieldErrors = fieldErrors;
        this.violationErrors = violationErrors;
    }

    /**
     * MethodArgumentNotValidException에 대한 ErrorResponse 객체를 생성
     * 해당 에러 정보를 얻기 위해 필요한 것이 BindingResult 객체이기 때문에
     * of() 메서드를 호출하는 쪽에서 BindingResult 객체를 파라미터로 넘겨주면 된다.
     *
     * 파라미터로 전달 받은 BindingResult 객체를 가지고 에러 정보를 추출하고 가공하는 일은
     * static 멤버 클래스인 FieldError 클래스에게 위임하고 있다.
     */
    public static ErrorResponse of(BindingResult bindingResult) {
        return new ErrorResponse(FieldError.of(bindingResult), null);
    }

    /**
     * ConstraintViolationException에 대한 ErrorResponse 객체를 생성
     * 해당 에러 정보를 얻기 위해 필요한 것이 Set<ConstraintViolation<?>> 객체이기 때문에
     * of() 메서드를 호출하는 쪽에서 Set<ConstraintViolation<?>> 객체를 파라미터로 넘겨주면 된다.
     *
     * 파라미터로 전달 받은 Set<ConstraintViolation<?>> 객체를 가지고 에러 정보를 추출하고 가공하는 일은
     * static 멤버 클래스인 ConstraintViolationError 클래스에게 위임하고 있다.
     */
    public static ErrorResponse of(Set<ConstraintViolation<?>> violations) {
        return new ErrorResponse(null, ConstraintViolationError.of(violations));
    }

    // 필드(DTO 클래스의 멤버 변수)의 유효성 검증에서 발생하는 에러 정보를 생성한다.
    @Getter
    public static class FieldError {
        private String field;
        private Object rejecteValue;
        private String reason;

        public FieldError(String field, Object rejecteValue, String reason) {
            this.field = field;
            this.rejecteValue = rejecteValue;
            this.reason = reason;
        }

        public static List<FieldError> of(BindingResult bindingResult) {
            final List<org.springframework.validation.FieldError> fieldErrors =
                    bindingResult.getFieldErrors();

            return fieldErrors.stream()
                    .map(error -> new FieldError(
                            error.getField(),
                            error.getRejectedValue(),
                            error.getDefaultMessage()))
                    .collect(Collectors.toList());
        }
    }

    // URI 변수 값에 대한 에러 정보를 생성한다.
    @Getter
    public static class ConstraintViolationError {
        private String propertyPath;
        private Object rejectedValue;
        private String reason;

        public ConstraintViolationError(String propertyPath, Object rejectedValue, String reason) {
            this.propertyPath = propertyPath;
            this.rejectedValue = rejectedValue;
            this.reason = reason;
        }

        public static List<ConstraintViolationError> of(
                Set<ConstraintViolation<?>> constraintViolations
        ) {
            return constraintViolations.stream()
                    .map(constraintViolation -> new ConstraintViolationError(
                            constraintViolation.getPropertyPath().toString(),
                            constraintViolation.getInvalidValue().toString(),
                            constraintViolation.getMessage()))
                    .collect(Collectors.toList());
        }
    }
}
```
