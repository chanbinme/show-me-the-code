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
package hobin.toyBoard.response;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;

import javax.validation.ConstraintViolation;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
public class ErrorResponse {

    private List<FieldError> fieldErrors;
    private List<FieldError.ConstraintViolationError> violationErrors;

    public ErrorResponse(List<FieldError> fieldErrors, List<FieldError.ConstraintViolationError> violationErrors) {
        this.fieldErrors = fieldErrors;
        this.violationErrors = violationErrors;
    }

    public static ErrorResponse of(BindingResult bindingResult) {
        return new ErrorResponse(FieldError.of(bindingResult), null);
    }

    public static ErrorResponse of(Set<ConstraintViolation<?>> violations) {
        return new ErrorResponse(null, FieldError.ConstraintViolationError.of(violations));
    }

    @Getter
    @AllArgsConstructor(access = AccessLevel.PRIVATE)
    public static class FieldError {
        private String field;
        private Object rejectValue;
        private String reason;

        public static List<FieldError> of(BindingResult bindingResult) {
            final List<org.springframework.validation.FieldError> fieldErrors = bindingResult.getFieldErrors();

            return fieldErrors.stream()
                    .map(error -> new FieldError(
                            error.getField(),
                            error.getRejectedValue() == null ?
                            "" : error.getRejectedValue().toString(),
                            error.getDefaultMessage()))
                    .collect(Collectors.toList());
        }
        
        @Getter
        @AllArgsConstructor(access = AccessLevel.PRIVATE)
        public static class ConstraintViolationError {
            private String propertyPath;
            private Object rejectedValue;
            private String reason;

            public static List<ConstraintViolationError> of(
                    Set<ConstraintViolation<?>> constraintViolations) {
                return constraintViolations.stream()
                        .map(constraintViolation -> new ConstraintViolationError(
                                constraintViolation.getPropertyPath().toString(),
                                constraintViolation.getInvalidValue().toString(),
                                constraintViolation.getMessage()
                        )).collect(Collectors.toList());
            }
            
        }
    }
}

```
