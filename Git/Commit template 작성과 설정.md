# Commit template 작성과 설정

## git message 파일 생성
- .gitmessage 파일을 생성합니다
```
$ touch ~/.gitmessage.txt
```

## Commit template 작성
- editor를 사용해서 .gitmessage 파일에 Commit template를 작성합니다. (필자는 vim을 사용했다.)
```
$ vim ~/.gitmessage.txt
```
```
# Title Message
# <type>(<scope>) - [#issueNumber-]: <subject>
# ex) feat - #123: 로그인 기능 추가
##### Subject 50 characters ################# -> |

# 한 줄 공백. subject과 body 구분

# Body Message (Optional)
######## Body 72 characters ####################################### -> |

# Footer (Optional)
# <type>: [#issueNumber-]
# ex) Resolves: #123

# --- COMMIT END ---
# Title type can be
#   feat    : 새로운 기능 추가
#   fix     : 버그 수정
#  design   : CSS등 사용자 UI 디자인 변경
# Title Message
# <type>(<scope>) - [#issueNumber-]: <subject>
# ex) feat - #123: 로그인 기능 추가
##### Subject 50 characters ################# -> |

# 한 줄 공백. subject과 body 구분

# Body Message (Optional)
######## Body 72 characters ####################################### -> |

# Footer (Optional)
# <type>: [#issueNumber-]
# ex) Resolves: #123

# --- COMMIT END ---
# Title type can be
#   feat    : 새로운 기능 추가
#   fix     : 버그 수정
#  design   : CSS등 사용자 UI 디자인 변경
#  refactor : 코드 리팩토링
#  comment  : 주석 추가 및 수정
#   style   : 코드에 영향을 주지 않는 변경사항
#   docs    : 문서 수정
#   test    : 테스트 추가, 테스트 리팩토링
```

## 템플릿 지정
- 작성한 .gitmessage 파일을 템플릿으로 지정합니다. commit.template에 설정하면 git commit 명령이 실행되는 편집기에 해당 템플릿을 기본으로 넣어줍니다. 
```
$ git config --global commit.template ~/.gitmessage.txt
```

## editor 설정
- editor를 설정합니다. 아무것도 설정하지 않으면 vi을 기본 에디터로 사용합니다. 
```
git config --global core.editor [사용할 editor]
```
```
# vim을 기본 에디터로 설정
git config --global core.editor vim 

# vscode를 기본 에디터로 설정
git config --global core.editor code --wait
```

## git 전역 설정이 잘 되었는지 확인
- 다음 명령어를 실행하여 기본 편집기가 잘 설정되었는지 확인할 수 있습니다
```
git config --global -e
```
```
[user]
        name = coldbean
        email = gksmfcksqls@gmail.com
[core]
        editor = vim	# vim이 기본 에디터로 설정되어있는 것을 확인할 수 있습니다.
        autocrlf = input
[filter "lfs"]
        process = git-lfs filter-process
        required = true
        clean = git-lfs clean -- %f
        smudge = git-lfs smudge -- %f
[commit]
        template = /Users/happy_bin/.gitmessage.txt # 작성한 .gitmessage파일이 템플릿 설정되어 있습니다.
[color]
        ui = auto
```

## 잘 실행되는지 확인 해보자!
- 커밋을 날려보자
```
git commit -a
```
![](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FcNn5NQ%2FbtrTT7REub6%2FiAV3GZrboq9gUV5NcEDU91%2Fimg.png)

## 참고
https://git-scm.com/book/en/v2/Customizing-Git-Git-Configuration