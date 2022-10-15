package main.java.hello.core;

import hello.core.member.Grade;
import hello.core.member.Member;
import hello.core.member.MemberService;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;

public class MemberApp {
    public static void main(String[] args) {
//        AppConfig appConfig = new AppConfig();
//        MemberService memberService = appConfig.memberService();

        /**
         * ApplicationContext를 스프링 컨테이너라고 한다.
         * new AnnotationConfigApplicationContext()으로 생성해준다.
         * 파라미터 안에 @Bean이 붙은 메서드를 스프링 컨테이너에 저장해서 관리해준다.
         * */
        ApplicationContext ac = new AnnotationConfigApplicationContext(AppConfig.class);
        /** 이름은 "memberService"이고 타입은 Memberservice.class인 Bean을 가져와줘 */
        MemberService memberService = ac.getBean("memberService", MemberService.class);

        Member memberA = new Member(1L, "memberA", Grade.VIP);
        memberService.join(memberA);

        Member findMember = memberService.findMember(1L);
        System.out.println("new member = " + memberA.getName());
        System.out.println("finder Member = " + findMember.getName());
    }
}
