# AWS Pipeline으로 배포 자동화하기

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/7e850847-4d14-4777-a5f3-e216450e4109/Untitled.png)

- AWS 개발자 도구 서비스를 이용해서 배포 자동화 파이프라인을 구축해야 한다.
    - CodePipeline을 이용해서 각 단계를 연결하는 파이프라인을 구축한다.
    - Source 단계에서 소스 코드가 저장된 GitHub 리포지토리를 연결한다.
    - Build 단계에서 CodeBuild 서비스를 이용하여 EC2 인스턴스로 빌드된 파일을 전달한다.
    - Deploy 단계에서 CodeDeploy 서비스를 이용하여 EC2 인스턴스에 변경 사항을 실시간으로 반영한다.
- 나중에 변경사항을 GitHub 리포지토리에 반영했을 경우, 배포 과정이 자동으로 진행되어야 한다.
- 배포 과정에서 오류가 생길 경우, log 파일을 참조하여 문제점을 확인할 수 있어야 한다.
- 배포한 프로젝트의 View(Client)가 없어도 Postman을 통해 확인할 수 있다.

## 개발 환경 구축

> 개인 PC의 로컬이 아닌 EC2 인스턴스에서 진행한다.
> 

### 1. JAVA 설치

- 패키미 매니저가 관리하는 패키지의 정보를 최신 상태로 업데이트

```bash
$ sudo apt update
```

- java 설치

```bash
$ sudo apt install openjdk-11-jre-headless
```

```bash
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

- Java 설치 여부 확인

```bash
$ java -version
```

### 2. AWS CLI 설치

- AWS CLI 설치. [공식문서](https://docs.aws.amazon.com/ko_kr/cli/latest/userguide/getting-started-install.html) 참고

```bash
$ curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
$ sudo apt install unzip
$ unzip awscliv2.zip
$ sudo ./aws/install
```

- AWS CLI 설치 여부 확인

```bash
$ aws --version

aws-cli/2.1.39 Python/3.8.8 Darwin/20.4.0 exe/x86_64 prompt/off
# 이런식의 문구가 보인다면 설치가 성공적으로 마무리된 것
```

### 3. CodeDeploy Agent 설치

- CodeDeploy Agent 설치

```bash
$ sudo apt update
$ sudo apt install ruby-full                # [Y / n] 선택시 Y 입력
$ sudo apt install wget
$ cd /home/ubuntu
$ sudo wget https://aws-codedeploy-ap-northeast-2.s3.ap-northeast-2.amazonaws.com/latest/install
$ sudo chmod +x ./install
$ sudo ./install auto > /tmp/logfile
```

- 서비스가 실행중인지 확인

```bash
$ sudo service codedeploy-agent status
```

- `active(running)` 문구를 확인했다면 정상적으로 실행중인 것이다.