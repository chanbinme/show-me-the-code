package 추상화 연습;

public class Purrinkle extends Chicken {
    @Override
    protected void grade() {
        System.out.println("치킨 인기투표 1등을 차지했어요.");
    }

    @Override
    protected void discription() {
        System.out.println("BHC의 역작. 뿌링 시즈닝을 뿌린 치킨에 에멘탈 치즈, 요거트 베이스의 뿌링뿌링 소스에 찍어 먹습니다.");
    }

    @Override
    protected void taste() {
        System.out.println("달콤짭짤한 맛");
    }
}

