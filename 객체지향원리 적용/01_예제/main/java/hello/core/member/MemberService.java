package main.java.hello.core.member;

public interface MemberService {
    /* member 생성 */
    void join(Member member);
    /* member 찾기 */
    Member findMember(Long memberId);
}
