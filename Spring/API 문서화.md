## 의존성 주입

### build.gradle

```groovy
plugins {
	id 'org.springframework.boot' version '2.7.1'
	id 'io.spring.dependency-management' version '1.0.11.RELEASE'
	id "org.asciidoctor.jvm.convert" version "3.3.2"    // (1)
	id 'java'
}

group = 'com.codestates'
version = '0.0.1-SNAPSHOT'
sourceCompatibility = '11'

repositories {
	mavenCentral()
}

// (2)
ext {
	set('snippetsDir', file("build/generated-snippets"))
}

// (3)
configurations {
	asciidoctorExtensions
}

dependencies {
       // (4)
	testImplementation 'org.springframework.restdocs:spring-restdocs-mockmvc'
  
  // (5) 
	asciidoctorExtensions 'org.springframework.restdocs:spring-restdocs-asciidoctor'

	implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
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

// (6)
tasks.named('test') {
	outputs.dir snippetsDir
	useJUnitPlatform()
}

// (7)
tasks.named('asciidoctor') {
	configurations "asciidoctorExtensions"
	inputs.dir snippetsDir
	dependsOn test
}

// (8)
task copyDocument(type: Copy) {
	dependsOn asciidoctor            // (8-1)
	from file("${asciidoctor.outputDir}")   // (8-2)
	into file("src/main/resources/static/docs")   // (8-3)
}

build {
	dependsOn copyDocument  // (9)
}

// (10)
bootJar {
	dependsOn copyDocument    // (10-1)
	from ("${asciidoctor.outputDir}") {  // (10-2)
		into 'static/docs'     // (10-3)
	}
}
```

- (1)에서는 `.adoc` 파일 확장자를 가지는 AsciiDoc 문서를 생성해주는 Asciidoctor를 사용하기 위한 플러그인을 추가한다.
- (2)에서는 `ext` 변수의 `set()` 메서드를 이용해서 API 문서 스니핏이 생성될 경로를 지정한다.
- (3)에서는 AsciiDoctor에서 사용되는 의존 그룹을 지정하고 있다. :asciidoctor task가 실행되면 내부적으로 (3)에서 지정한 ‘`asciidoctorExtensions`’라는 그룹을 지정한다.
- (4)에서 'org.springframework.restdocs:spring-restdocs-mockmvc'를 추가함으로써 spring-restdocs-core와 spring-restdocs-mockmvc 의존 라이브러리가 추가된다.
- (5)에서 spring-restdocs-asciidoctor 의존 라이브러리를 추가한다. (3)에서 지정한 asciidoctorExtensions 그룹에 의존 라이브러리가 포함된다.
- (6)에서는 :test task 실행 시, API 문서 생성 스니핏 디렉토리 경로를 설정한다.
- (7)에서는 :asciidoctor task 실행 시, Asciidoctor 기능을 사용하기 위해 :asciidoctor task에 `asciidoctorExtensions` 을 설정한다.
- (8)은 `:build` task 실행 전에 실행되는 task다. `:copyDocument` task가 수행되면 index.html 파일이 `src/main/resources/static/docs` 에 copy 되며, copy된 index.html 파일은 API 문서를 파일 형태로 외부에 제공하기 위한 용도로 사용할 수 있다.
    1. (8-1)에서는 `:asciidoctor` task가 실행된 후에 task가 실행 되도록 의존성을 설정한다.
    2. (8-2)에서는 "`build/docs/asciidoc/"` 경로에 생성되는 index.html을 copy한 후,
    3. (8-3)의 "`src/main/resources/static/docs`" 경로로 index.html을 추가해 준다.
- (9)에서는 `:build` task가 실행되기 전에 `:copyDocument` task가 먼저 수행 되도록 한다.
- (10)에서는 애플리케이션 실행 파일이 생성하는 `:bootJar` task 설정이다.
    1. (10-1)에서는 `:bootJar` task 실행 전에 `:copyDocument` task가 실행 되도록 의존성을 설정한다.
    2. (10-2)에서는 Asciidoctor 실행으로 생성되는 index.html 파일을 jar 파일 안에 추가해 준다.
       jar 파일에 index.html을 추가해 줌으로써 웹 브라우저에서 접속(`http://localhost:8080/docs/index.html`) 후, API 문서를 확인할 수 있다.

## API 문서 스니핏을 사용하기 위한 템플릿 생성

- Gradle 기반 프로젝트 : `src/docs/asciidoc/` 경로에 템플릿 문서(index.adoc) 생성

## ControllerTest

```java
package toyproject.todo.todo.controller;

import com.google.gson.Gson;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.restdocs.AutoConfigureRestDocs;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.mapping.JpaMetamodelMappingContext;
import org.springframework.http.MediaType;
import org.springframework.restdocs.payload.JsonFieldType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;
import toyproject.todo.todo.dto.TodoPatchDto;
import toyproject.todo.todo.dto.TodoPostDto;
import toyproject.todo.todo.dto.TodoResponseDto;
import toyproject.todo.todo.entity.Todo;
import toyproject.todo.todo.mapper.TodoMapper;
import toyproject.todo.todo.service.TodoService;

import java.net.URI;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doNothing;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.*;
import static org.springframework.restdocs.payload.PayloadDocumentation.*;
//import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.*;
import static org.springframework.restdocs.request.RequestDocumentation.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(TodoController.class)
@MockBean(JpaMetamodelMappingContext.class)
@AutoConfigureRestDocs
class TodoControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private Gson gson;

    @MockBean
    private TodoService todoService;

    @MockBean
    private TodoMapper mapper;

    @Test
    public void postTodoTest() throws Exception {
        // given
        TodoPostDto post = new TodoPostDto("양치하기", 1L, false);
        String content = gson.toJson(post);
        Todo todo = new Todo(1L, "양치하기", 1L, false);
        TodoResponseDto responseDto = new TodoResponseDto(1L, "양치하기", 1L, false);

        // when
        given(mapper.todoPostToTodo(Mockito.any(TodoPostDto.class))).willReturn(todo);
        given(todoService.saveTodo(Mockito.any(Todo.class))).willReturn(todo);
        given(mapper.todoToTodoResponse(Mockito.any(Todo.class))).willReturn(responseDto);

        ResultActions actions =
                mockMvc.perform(
                        post("/todos")
                                .accept(MediaType.APPLICATION_JSON)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(content)
                );

        // then
        actions
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.title").value(post.getTitle()))
                .andExpect(jsonPath("$.order").value(post.getOrder()))
                .andExpect(jsonPath("$.completed").value(post.isCompleted()))
                .andDo(document("post-todo",
                        preprocessRequest(prettyPrint()),
                        preprocessResponse(prettyPrint()),
                        requestFields(
                                List.of(
                                        fieldWithPath("title").type(JsonFieldType.STRING).description("해야 할 일"),
                                        fieldWithPath("order").type(JsonFieldType.NUMBER).description("우선순위"),
                                        fieldWithPath("completed").type(JsonFieldType.BOOLEAN).description("완료 여부")
                                )
                        ),
                        responseFields(
                                List.of(
                                        fieldWithPath("todoId").type(JsonFieldType.NUMBER).description("Todo 식별자"),
                                        fieldWithPath("title").type(JsonFieldType.STRING).description("해야 할 일"),
                                        fieldWithPath("order").type(JsonFieldType.NUMBER).description("우선 순위"),
                                        fieldWithPath("completed").type(JsonFieldType.BOOLEAN).description("완료 여부")
                                )
                        )
                ));
    }

    @Test
    public void getTodoTest() throws Exception {
        // given
        Todo todo = new Todo(1L, "양치하기", 1L, false);
        TodoResponseDto responseDto = new TodoResponseDto(1L, "양치하기", 1L, false);

        // when
        given(todoService.findTodo(Mockito.anyLong())).willReturn(todo);
        given(mapper.todoToTodoResponse(Mockito.any(Todo.class))).willReturn(responseDto);

        ResultActions actions = mockMvc.perform(
                get("/todos/{todo-id}", todo.getTodoId())
                        .accept(MediaType.APPLICATION_JSON)
        );

        // then
        actions
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.todoId").value(todo.getTodoId()))
                .andExpect(jsonPath("$.title").value(todo.getTitle()))
                .andExpect(jsonPath("$.order").value(todo.getOrder()))
                .andExpect(jsonPath("$.completed").value(todo.isCompleted()))
                .andDo(document("get-todo",
                        preprocessRequest(prettyPrint()),
                        preprocessResponse(prettyPrint()),
                        pathParameters(
                                Arrays.asList(
                                        parameterWithName("todo-id").description("Todo 식별자"))
                        ),
                        responseFields(
                                Arrays.asList(
                                        fieldWithPath("todoId").type(JsonFieldType.NUMBER).description("Todo 식별자"),
                                        fieldWithPath("title").type(JsonFieldType.STRING).description("해야 할 일"),
                                        fieldWithPath("order").type(JsonFieldType.NUMBER).description("우선 순위"),
                                        fieldWithPath("completed").type(JsonFieldType.BOOLEAN).description("완료 여부")
                                )
                        )
                ));
    }

    @Test
    public void getTodosTest() throws Exception {
        // given
        Todo todo1 = new Todo(1L, "양치하기", 1L, false);
        Todo todo2 = new Todo(2L, "세수하기", 2L, false);
        TodoResponseDto responseDto1 = new TodoResponseDto(1L, "양치하기", 1L, false);
        TodoResponseDto responseDto2 = new TodoResponseDto(2L, "세수하기", 2L, false);

        int page = 1;
        int size = 10;

        Page<Todo> pageTodos = new PageImpl<>(List.of(todo1, todo2),
                PageRequest.of(page - 1, size), 2);
        List<TodoResponseDto> responseDtos = List.of(responseDto1, responseDto2);

        // when
        given(todoService.findTodos(Mockito.anyInt(), Mockito.anyInt())).willReturn(pageTodos);
        given(mapper.todosToTodoResponses(Mockito.anyList())).willReturn(responseDtos);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("page", String.valueOf(page));
        params.add("size", String.valueOf(size));

        ResultActions actions = mockMvc.perform(
                get("/todos")
                        .params(params)
                        .accept(MediaType.APPLICATION_JSON)
        );
        // then
        actions
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.[0].todoId").value(todo1.getTodoId()))
                .andExpect(jsonPath("$.[0].title").value(todo1.getTitle()))
                .andExpect(jsonPath("$.[0].order").value(todo1.getOrder()))
                .andExpect(jsonPath("$.[0].completed").value(todo1.isCompleted()))
                .andExpect(jsonPath("$.[1].todoId").value(todo2.getTodoId()))
                .andExpect(jsonPath("$.[1].title").value(todo2.getTitle()))
                .andExpect(jsonPath("$.[1].order").value(todo2.getOrder()))
                .andExpect(jsonPath("$.[1].completed").value(todo2.isCompleted()))
                .andDo(document("get-todos",
                        preprocessRequest(prettyPrint()),
                        preprocessResponse(prettyPrint()),
                        requestParameters(
                                List.of(
                                        parameterWithName("page").description("Page 번호"),
                                        parameterWithName("size").description("Page Size")
                                )),
                        responseFields(
                                List.of(
                                        fieldWithPath("[].todoId").type(JsonFieldType.NUMBER).description("Todo 식별자"),
                                        fieldWithPath("[].title").type(JsonFieldType.STRING).description("해야 할 일"),
                                        fieldWithPath("[].order").type(JsonFieldType.NUMBER).description("우선 순위"),
                                        fieldWithPath("[].completed").type(JsonFieldType.BOOLEAN).description("완료 여부")
                                )
                        )
                ));
    }

    @Test
    public void patchTodoTest() throws Exception {
        // given
        TodoPatchDto patchDto = TodoPatchDto.builder().title("양치하기").build();
        Todo todo = new Todo(1L, "양치하기", 1L, false);
        TodoResponseDto responseDto = new TodoResponseDto(1L, "양치하기", 1L, false);
        String content = gson.toJson(patchDto);

        // when
        given(mapper.todoPatchToTodo(Mockito.any(TodoPatchDto.class))).willReturn(todo);
        given(todoService.updateTodo(Mockito.any(Todo.class))).willReturn(todo);
        given(mapper.todoToTodoResponse(Mockito.any(Todo.class))).willReturn(responseDto);

        ResultActions actions = mockMvc.perform(
                patch("/todos/{todo-id}", 1L)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(content)
        );

        // then
        actions
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.todoId").value(1L))
                .andExpect(jsonPath("$.title").isNotEmpty())
                .andExpect(jsonPath("$.order").isNotEmpty())
                .andExpect(jsonPath("$.completed").isNotEmpty())
                .andDo(document("patch-todo",
                        preprocessRequest(prettyPrint()),
                        preprocessResponse(prettyPrint()),
                        pathParameters(
                                Arrays.asList(
                                        parameterWithName("todo-id").description("Todo 식별자"))
                        ),
                        requestFields(
                                List.of(
                                        fieldWithPath("title").type(JsonFieldType.STRING).description("해야 할 일").optional(),
                                        fieldWithPath("order").type(JsonFieldType.NUMBER).description("우선 순위").optional(),
                                        fieldWithPath("completed").type(JsonFieldType.BOOLEAN).description("완료 여부").optional())
                        ),
                        responseFields(
                                List.of(
                                        fieldWithPath("todoId").type(JsonFieldType.NUMBER).description("Todo 식별자"),
                                        fieldWithPath("title").type(JsonFieldType.STRING).description("해야 할 일"),
                                        fieldWithPath("order").type(JsonFieldType.NUMBER).description("우선 순위"),
                                        fieldWithPath("completed").type(JsonFieldType.BOOLEAN).description("완료 여부")
                                )
                        )
                ));
    }

    @Test
    public void deleteTodoTest() throws Exception {
        // given
        Todo todo = new Todo(1L, "양치하기", 1L, false);
        doNothing().when(todoService).deleteTodo(todo.getTodoId());

        // when
        ResultActions actions = mockMvc.perform(
                delete("/todos/{todo-id}", 1L)
        );

        // then
        actions.andExpect(status().isNoContent())
                .andDo(document("delete-todo",
                        pathParameters(List.of(
                                parameterWithName("todo-id").description("Todo 식별자")
                        ))));
    }
}
```

`@MockBean(JpaMetamodelMappingContext.class)` : JPA에서 사용하는 Bean들을 Mock객체로 주입해주는 설정이다. Spring Boot 기반의 테스트는 항상 최상위 패키지 경로에 있는 xxxxxxxxApplication 클래스를 찾아서 실행한다.

```java
@EnableJpaAuditing
@SpringBootApplication
public class RestDocsApplication {

	public static void main(String[] args) {
		SpringApplication.run(Section3Week3RestDocsApplication.class, args);
	}

}
```

- `@EnableJpaAuditing` 을 xxxxxxApplication 클래스에 추가하게 되면 JPA와 관련된 Bean을 필요로 하기 때문에 `@WebMvcTest` 애너테이션을 사용해서 테스트를 진행 할 경우에는 JpaMetamodelMappingContext를 Mock 객체로 주입해 주어야 합니다.

## 테스트 실행

- API 스펙 정보가 포함된 테스트 케이스가 완성되면 테스트 케이스를 실행한다.
- 테스트 케이스가 ‘passed’이면 API 스펙 정보를 기반으로 문서 스니핏이 만들어진다.

  ![스크린샷 2022-12-01 오전 12.00.39.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/15d95cb1-a885-49ff-a64f-58d55efb336b/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2022-12-01_%E1%84%8B%E1%85%A9%E1%84%8C%E1%85%A5%E1%86%AB_12.00.39.png)


## index.adoc 내용 추가

```markdown
= Todo 애플리케이션
:sectnums:
:toc: left
:toclevels: 4
:toc-title: Table of Contents
:source-highlighter: prettify

Chan Bin Kim <gksmfcksqls@gmail.com>

v1.0.0, 2022.11.29

***
== TodoController
=== Todo 등록
.curl-request
include::{snippets}/post-todo/curl-request.adoc[]

.http-request
include::{snippets}/post-todo/http-request.adoc[]

.request-fields
include::{snippets}/post-todo/request-fields.adoc[]

.http-response
include::{snippets}/post-todo/http-response.adoc[]

.response-fields
include::{snippets}/post-todo/response-fields.adoc[]

=== Todo 수정
.curl-request
include::{snippets}/patch-todo/curl-request.adoc[]

.http-request
include::{snippets}/patch-todo/http-request.adoc[]

.request-fields
include::{snippets}/patch-todo/request-fields.adoc[]

.path-parameters
include::{snippets}/patch-todo/path-parameters.adoc[]

.http-response
include::{snippets}/patch-todo/http-response.adoc[]

.response-fields
include::{snippets}/patch-todo/response-fields.adoc[]

=== Todo 정보 가져오기
.curl-request
include::{snippets}/get-todo/curl-request.adoc[]

.http-request
include::{snippets}/get-todo/http-request.adoc[]

.path-parameters
include::{snippets}/get-todo/path-parameters.adoc[]

.http-response
include::{snippets}/get-todo/http-response.adoc[]

.response-fields
include::{snippets}/get-todo/response-fields.adoc[]

=== 모든 Todo 정보 가져오기
.curl-request
include::{snippets}/get-todos/curl-request.adoc[]

.http-request
include::{snippets}/get-todos/http-request.adoc[]

.request-parameters
include::{snippets}/get-todos/request-parameters.adoc[]

.http-response
include::{snippets}/get-todos/http-response.adoc[]

.response-fields
include::{snippets}/get-todos/response-fields.adoc[]

=== Todo 삭제
.curl-request
include::{snippets}/delete-todo/curl-request.adoc[]

.http-request
include::{snippets}/delete-todo/http-request.adoc[]

.path-parameters
include::{snippets}/delete-todo/path-parameters.adoc[]

.http-response
include::{snippets}/delete-todo/http-response.adoc[]
```

- 템플릿 문서 작성이 끝나면 Gradle의 `:build` 또는 `:bootJar` task 명령을 실행해서 `index.adoc` 를 `index.html`  파일로 변환한다.
- 정상적으로 빌드가 종료되면 `src/main/resources/static/docs` 디렉토리에 `index.html` 파일이 생성된다.
- 애플리케이션을 실행하고 아래 URL을 웹 브라우저에 입력하면 api문서를 확인할 수 있다.
    - `http://localhost:8080/docs/index.html`

![Untitled](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/2a58c0dc-d55d-4c30-9cf1-9e1d3d58dd33/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221130%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221130T152135Z&X-Amz-Expires=86400&X-Amz-Signature=d2628686a3d57fc3d01307132d473fffa4f6645bc35b178eb2d8eef199497a4e&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject)