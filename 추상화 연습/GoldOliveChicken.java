package 추상화 연습;

public class GoldOliveChicken extends Chicken {
    @Override
    protected void grade() {
        System.out.println("치킨 인기투표 2등을 차지했어요.");
    }

    @Override
    protected void discription() {
        System.out.println("BBQ의 대표메뉴. 줄여서 황올이라고 부릅니다. 맛 자체는 확실히 다른 후라이드 치킨과는 차별화된 맛을 자랑합니다. 블라인드 테스트에서 바로 맞출 수 있을정도입니다.");
    }

    @Override
    protected void taste() {
        System.out.println("매콤짭짤한 맛");
    }
}


