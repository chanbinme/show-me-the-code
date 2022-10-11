package 추상화 연습;

public class HoneyCombo extends Chicken {
    @Override
    protected void grade() {
        System.out.println("치킨 인기투표 3등을 차지했어요.");
    }

    @Override
    protected void discription() {
        System.out.println("교촌치킨의 대표메뉴. 교촌 오리지날에 꿀을 더한 단짠 스타일의 치킨입니다.");
    }

    @Override
    protected void taste() {
        System.out.println("달콤짭짤한 맛");
    }
}

