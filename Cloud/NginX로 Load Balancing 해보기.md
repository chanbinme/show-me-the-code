# NginX - Load Balancer

![Untitled](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/aa99050a-a9ca-4ee2-b061-f14407f051cc/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221210%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221210T061717Z&X-Amz-Expires=86400&X-Amz-Signature=b45937f17716e073575d0d64595843fca5c8adb8b4ac4d221e1c001087cafd8a&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject)

- NginX을 이용해서 로컬 환경에서 로드밸런싱을 구성해보자

### 1. 두 개의 스프링부트 서버 실행

- 프로젝트를 빌드한다.

```bash
$ ./gradlew build
```

- 빌드 파일을 실행한다.(포트를 변경하지 않은 경우 8080번 포트에서 실행된다)

```bash
# 실행파일은 /build/libs에 있다.
$ java -jar sample-0.0.1-SNAPSHOT.jar
```

```bash
# http://localhost:8080/ 출력된 텍스트
Hello World, Hello BE Bootcamp! @PID : 90844
```

- 빌드 파일을 이용해서 새 터미널에 다른 포트에서 실행한다.

```bash
$ java -Dserver.port=8081 -jar sample-0.0.1-SNAPSHOT.jar
```

```bash
# http://localhost:8081/ 출력된 텍스트
Hello World, Hello BE Bootcamp! @PID : 94774
```

- 이제 로드 밸런싱을 구성해보자

## 2. NginX 설정파일 수정

```bash
$ nginx -t
nginx: the configuration file /usr/local/etc/nginx/nginx.conf syntax is ok
nginx: configuration file /usr/local/etc/nginx/nginx.conf test is successful

# 위에 나오는 파일 경로 확인하여 수정
$ nano /usr/local/etc/nginx/nginx.conf
```

```bash
http {
	upstream backend {
		server localhost:8080;
		server localhost:8081;
	}
server {
	...
	location / {
		proxy_pass http://backend;
	}
}
```

- `backend` 라는 서버 그룹을 만든 뒤 그룹 자체로 전달을 하는 구조이다. 서버 이름은 다른 이름을 변경 가능하다.
- 이 때 그룹에 속한 각 서버의 값은 위에서 실행한 두 개의 스프링 프로젝트 접속 URL을 작성한다. 각각의 포트 번호까지 함께 작성한다.
- location의 `proxy_pass` 값으로 해당 서버 그룹을 설정한다.
- NginX의 포트는 80번으로 설정되어 있기 때문에 포트를 생략한 `[localhost](http://localhost)` 로 접속시 8080번 포트와 8081번 포트가 번갈아 연결된다.

```bash
http {
    include       mime.types;
    default_type  application/octet-stream;

    #log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
    #                  '$status $body_bytes_sent "$http_referer" '
    #                  '"$http_user_agent" "$http_x_forwarded_for"';

    #access_log  logs/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    #gzip  on;
    upstream backend {
        server localhost:8080;
        server localhost:8081;
    }
    server {
        listen       80;
        server_name  localhost;

        #charset koi8-r;

        #access_log  logs/host.access.log  main;

        location / {
            proxy_pass http://backend;
        }
```

## 3. 로드밸런싱 결과

- NginX를 실행한다.

```bash
$ brew services start nginx
```

```bash
# http://localhost 새로고침때마다 번갈아 나옴
Hello World, Hello BE Bootcamp! @PID : 94774
Hello World, Hello BE Bootcamp! @PID : 90844
```