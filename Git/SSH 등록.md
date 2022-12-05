> SSH는 Secure Shell의 줄임말(Secure Shell)로, 보안이 강화된 shell 접속을 뜻한다. CLI 환경(터미널)에서 다른 PC에 접속하거나 요청할 때 사용하며, 비대칭키를 이용해 사용자를 인증한다.

## SSH 키 생성

-   ssh 키는 비대칭키로 구성되며, 두 개의 키가 서로 대칭이 되지 않는 형태로 존재한다.
-   ssh-keygen 명령어는 경로 ~/.ssh./ 에 id\_rsa 와 id\_rsa.pub 를 생성한다.
    -   id\_rsa.pub : 누구에게나 공개해도 되는 공개키(Public Key)
    -   id\_rsa : 공개되면 안되는 개인키(Private Key)

```
ssh-keygen
```

-   생성된 키 페어 중 공개키를 복사하여 github에 등록한다.

## 공개키(Public Key) 복사

```
cat ~/.ssh/id_rsa.pub
```

-   화면에 출력된 키를 복사한다.

## Github에 공개키 등록

1.  Github 로그인 → 우측 상단의 프로필 이미지 클릭 → Settings 클릭
![](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FcNa2Nb%2FbtrSUqd4VwV%2F9GhE6b3IYRL69BcJSCZEG0%2Fimg.png)
![](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FbjnMqF%2FbtrSQU05BAe%2F9c5po4HCEoeh3OVkQorWI0%2Fimg.png)
2.  왼쪽 네비게이션에서 SSH and GPG keys 클릭 → 나타난 화면에서 초록색 버튼 New SSH Key 클릭 
![](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FcPBAr5%2FbtrSOxLSPdk%2F0TabBFgoPBd6d2xmR439Uk%2Fimg.png)
3.  Title 작성, Key에 복사해둔 공개키를 붙여넣는다. → Add SSH Key 버튼을 클릭
![](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FmY3Py%2FbtrSKQ6vRwh%2FWkXrLIdWUxZutSm6TpKkJ1%2Fimg.png)
4.  Confirm Access에서 Github 로그인에 필요한 비밀번호를 입력해 SSH key 등록을 승인
5.  SSH 공개키가 정상적으로 등록되었는지 확인하려면, 레포지토리를 SSH로 clone해본다.

