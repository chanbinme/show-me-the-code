package 추상화 연습;

public class ChickenManageApllication {
    public static void main(String[] args) {
        Chicken purrinkle = new Purrinkle();
        Chicken goldOliveChicken = new GoldOliveChicken();
        Chicken honeyCombo = new HoneyCombo();

        purrinkle.discription();
        goldOliveChicken.discription();
        honeyCombo.discription();
    }
}
