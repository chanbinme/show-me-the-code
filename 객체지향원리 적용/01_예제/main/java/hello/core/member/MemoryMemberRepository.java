package main.java.hello.core.member;

import java.util.Map;
import java.util.HashMap;

public class MemoryMemberRepository implements MemberRepository {
    /**
     * 구현체는 인터페이스와 다른 패키지에 놓는 것이 좋지만 간단한 예제를 위해 같은 패키지에 생성
     * 동시성 이슈가 있기 때문에 원래는 ConcurrentHashMap을 사용하지만 이 또한 간단한 예제를 위해 그냥 HahsMap 사용
     */
    private static Map<Long, Member> store = new HashMap<>();

    @Override
    public void save(Member member) {
        store.put(member.getId(), member);
    }

    @Override
    public Member findById(Long memberId) {
        return store.get(memberId);
    }
}
