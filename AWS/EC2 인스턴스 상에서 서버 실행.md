# ****EC2 인스턴스 상에서 서버 실행****

## **1. 인스턴스에 개발 환경 구축하기**

우리는 EC2 인스턴스를 생성하는 것이 가상 PC 한 대를 임대하는 것이라고 배웠습니다. 컴퓨터 운영체제를 처음 구입하면 필요한 프로그램을 설치해야 하듯이, EC2 인스턴스에 처음 접속하면 서버를 구동하는 데 필요한 개발 환경을 구축하는 것부터 시작해야 합니다. 저번 실습에서 EC2 인스턴스와 연결한 터미널에서 아래 명령어를 입력합니다. 패키지 매니저가 관리하는 패키지의 정보를 최신 상태로 업데이트하기 위해서 아래 명령어를 사용합니다.

```
$ sudo apt update
```

어느 정도 시간이 지나고 업데이트 과정이 끝나면 java를 설치해야 합니다.

```
$ sudo apt install openjdk-11-jre-headless
```

아래와 같은 확인창이 나올경우 "Y"를 입력하시면 됩니다.

```java
Reading package lists... Done
Building dependency tree
Reading state information... Done
The following additional packages will be installed:
  libasound2 libasound2-data libgraphite2-3 libharfbuzz0b
Suggested packages:
  libasound2-plugins alsa-utils libnss-mdns fonts-dejavu-extra fonts-ipafont-gothic fonts-ipafont-mincho fonts-wqy-microhei
  | fonts-wqy-zenhei fonts-indic
The following NEW packages will be installed:
  libasound2 libasound2-data libgraphite2-3 libharfbuzz0b openjdk-11-jre-headless
0 upgraded, 5 newly installed, 0 to remove and 70 not upgraded.
Need to get 37.9 MB of archives.
After this operation, 173 MB of additional disk space will be used.
Do you want to continue? [Y/n]
```

설치 과정이 마무리되면, java -version 명령어를 입력하여 java 라이브러리가 설치가 완료되었는지 확인합니다. 명령어를 입력했는데 오류가 난다면 java 설치 과정이 정상적으로 마무리되지 않은 것입니다.

## **2. git을 통해 서버 코드 클론 받기**

스프린트 코드가 저장된 깃헙 레포지토리 주소를 복사하고, `git clone` 명령어를 통해 EC2 인스턴스에 스프린트 코드를 클론 받습니다. 학습 초기에 clone을 위해 설정하셨던것과 같이, SSH등록이 필요합니다.
**[Section1 Git 유닛](https://urclass.codestates.com/content/8c3bedc6-2898-46c0-b482-5ce29a271bd7?playlist=1977)**를 참고하여 진행합니다.

> 관리해야할 EC2의 수가 늘어나게 되면 어떻게 될까요?
> 
> 
> GitHub에 등록된 SSH의 수가 EC2의 개수만큼 늘어나게 될 것입니다.
> **Cloud 실습이 모두 끝난 후** 새로 등록한 EC2의 SSH 정보를 삭제하여 관리합니다.
> 

```java
ubuntu@ip-172-31-41-164:~$ git clone git@github.com:codestates-seb/be-sprint-deployment.git
Cloning into 'im-sprint-practice-deploy'...
Username for 'https://github.com': kimcoding
Password for 'https://kimcoding@github.com:
...
```

정상적으로 클론했는지 확인하기 위해 터미널에 `ls` 명령어를 입력합니다. 스프린트 코드 폴더명이 보이면 정상적으로 다운로드가 완료된 것입니다. 터미널을 통해 스프린트 코드 안의 `DeployServer` 디렉토리로 이동합니다.

```java
cd be-sprint-deployment/DeployServer
```

이후 빌드작업을 진행합니다.

```java
./gradlew build
```

정상적으로 빌드가 완료되었으면 터미널에 `ls`명령어를 입력하면, `build`폴더를 확인할 수 있습니다.

## **3. EC2 인스턴스에서 서버 실행하기**

```
java -jar build/libs/DeployServer-0.0.1-SNAPSHOT.jar
```

해당 명령어를 이용하여, 빌드된 파일을 실행합니다.

![Untitled](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/b16dbd72-8faf-4fa4-9df9-5b8facb9591f/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221204%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221204T064844Z&X-Amz-Expires=86400&X-Amz-Signature=26084a8a6125daabcf5dfe2609027a01c9ba34cd5b1e6a2685ae83ec12914b31&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject)

위와 같은 메시지를 통해 정상적으로 서버가 실행되었음을 확인할 수 있습니다. 이제 EC2 인스턴스의 IP 주소로 접근해서 테스트를 진행합니다. IP 주소는 EC2 대시보드에서 생성한 EC2 인스턴스를 클릭하면 확인할 수 있습니다.

![Untitled](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/43e5d3de-0bd0-4056-819c-44afddeed6bb/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221204%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221204T064900Z&X-Amz-Expires=86400&X-Amz-Signature=825e0851e9a1ec2225d27f5fcb4062688d5354c82e386f3372a13700f7e33e8e&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject)

아래 화면에서 보라색으로 강조된 부분을 보시면, 두 가지 형태의 주소가 존재하는 것을 확인할 수 있습니다. 퍼블릭 IPv4 주소와 퍼블릭 IPv4 DNS는 형태만 다를 뿐 같은 주소입니다. 둘 중 어떤 주소를 사용하셔도 문제가 없습니다. 이번 실습에서는 퍼블릭 IPv4 DNS 주소를 이용하여 접속 테스트를 진행하겠습니다.

![Untitled](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/495d711f-2d9f-4001-ae7a-3bffe9c27697/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221204%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221204T064913Z&X-Amz-Expires=86400&X-Amz-Signature=abf6448c7393f7167daaabe9057a13aa358b079ec057d443bf7f55fdf5ae2983&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject)

EC2 인스턴스의 IP 주소로 접속하면 아래와 같은 화면을 볼 수 있습니다.

에러 없이 바로 접근이 가능한 이유는 여러분이 전달받은 EC2 인스턴스에는 이미 **보안 그룹**이 설정되어있기 때문입니다.

프로젝트가 실행중일 때 터미널에 `Ctrl + C` 단축키를 통해 실행중인 프로젝트를 강제종료 할 수 있습니다.