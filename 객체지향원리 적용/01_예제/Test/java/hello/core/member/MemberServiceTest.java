package Test.java.hello.core.member;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

public class MemberServiceTest {

    MemberService memberService = new MemberServiceImpl();

    /**
     * Test 코드는 선택이 아닌 필수다
     * 이 코드의 설계에는 큰 문제점이 있다.
     * 바로 의존관계가 인터페이스 뿐만 아니라 구현까지 모두 의존하는 문제점이 있다.
     */
    @Test
    void join() {
        // given
        Member member = new Member(1L, "memberA", Grade.VIP);

        // when
        memberService.join(member);
        Member findMember = memberService.findMember(1L);

        // then
        Assertions.assertThat(member).isEqualTo(findMember);
    }
}
