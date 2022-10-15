package main.java.hello.core.member;

public class MemberServiceImpl implements MemberService{

    /* 이 코드는 인터페이스뿐만 아니라 구현체까지 의존하는 문제가 있다 */
    private final MemberRepository memberRepository = new MemoryMemberRepository();

    @Override
    public void join(Member member) {
        memberRepository.save(member);
    }

    @Override
    public Member findMember(Long memberId) {
        return memberRepository.findById(memberId);
    }
}
