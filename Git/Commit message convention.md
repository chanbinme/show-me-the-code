# Commit message convention

**[Udacity Git Commit Message Style Guide](https://udacity.github.io/git-styleguide/), [conventionalcommits](https://www.conventionalcommits.org/en/v1.0.0/) 를 참고했습니다.**

해당 Convention은 **[Udacity Git Commit Message Style Guide](https://udacity.github.io/git-styleguide/)**

## 메시지 구조

커밋 메시지는 크게 제목, 본문, 꼬리말 세 가지 파트로 나누고 한 줄을 띄어 구분합니다.

```java
type(옵션): subject // 제목 

body(옵션) // 본문

footer(옵션) [#issueNumber-] // 꼬리말
```

- 제목 : 어떤 작업을 했는지 명확하게 드러나야하고, 너무 길지 않게 작성해야 합니다.
- 본문 : 긴 설명이 필요한 경우에 작성합니다. 어떻게 했는지가 아니라, 무엇을 왜 했는지를 작성합니다.
- 꼬리말 : 이슈 번호를 참조시킬 때 주로 사용합니다. 선택사항입니다.

## 제목

### type

- type은 subject와 함께 제목 내에 포함됩니다.
- `type: subject` 의 형태이며, `:` 뒤에만 띄어쓰기를 합니다.

| 타입 이름 | 설명 |
| --- | --- |
| feat | 새로운 기능 추가 |
| fix | 버그 수정 |
| design | CSS 등 사용자 UI 디자인 변경 |
| refactor | 코드 리팩토링 |
| comment | 주석 추가 및 수정 |
| style | 코드에 영향을 주지 않는 변경사항(오타 수정, 탭 사이즈 변경, 변수명 변경) |
| docs | 문서 수정 |
| test | 테스트 추가, 테스트 리팩토링 |
| chore | 빌드 부분 혹은 패키지 매니저 수정사항 |
| rename | 파일 혹은 폴더명을 수정하거나 옮기는 작업만인 경우 |
| remove | 파일을 삭제하는 작업만 수행한 경우 |

### subject

- subject는 type과 함께 제목 내에 포함됩니다.
- 명령조로 작성하며, 문장보다는 구문으로 작성합니다.
- 영문으로 작성할 경우 첫 글자는 대문자로 시작합니다.
- 끝에 마침표(.)를 사용하지 않습니다.
- 한 줄에 50자를 넘으면 안됩니다.

### 제목 예시

```java
feat: Add .gitignore

feat: .gitignore 추가
```

## 본문

- 모든 커밋이 본문을 사용해야 할만큼 복잡하지 않기 때문에 선택 사항입니다.
- 커밋에 대한 맥락과 부연 설명이 필요할 때 작성합니다.
- 어떻게보다 무엇을, 왜 변경했는지를 작성합니다.
- 본문을 작성할 때 제목과 본문 사이에 한 줄을 띄고 작성합니다.
- 한 줄에 72자를 넘지 않아야합니다.

## 꼬리말

- 꼬리말은 선택 사항이며 이슈 트래커 ID를 참조하는데 사용됩니다.
- 꼬리말은 `유형: #이슈 번호` 형식으로 작성합니다.
- 여러 개의 이슈 번호를 적을 때는 쉼표로 구분한다.

| 타입 이름 | 설명 |
| --- | --- |
| Resolves | 이슈를 해결했을 때 사용 (해당 이슈 닫음) |

### 최종 예시

```java
Feat: 추가 login 메서드

로그인 API 개발

Resolves: #123
```

```java
fix: Prevent racing of requests

Introduce a request id and a reference to latest request. Dismiss
incoming responses other than from latest request.

Resolevs: #123
```