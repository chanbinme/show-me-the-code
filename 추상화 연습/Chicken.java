package 추상화 연습;

public abstract class Chicken {
    protected String chickenType;
    protected double weight;
    protected String brandName;
    protected int price;

    protected abstract void grade();
    protected abstract void discription();
    protected abstract void taste();
}

