import java.util.ArrayList;

public class Stack {
    private ArrayList<Integer> listStack = new ArrayList<>();

    // push() : 스택에 데이터를 추가한다.
    public void push(Integer data) {
        listStack.add(data);
    }
    // pop() : 가장 나중에 추가된 데이터를 스택에서 삭제하고 삭제한 데이터를 리턴한다.
    public Integer pop() {
        if (listStack.isEmpty()) return null;
        else {
            return listStack.remove(listStack.size() - 1);
        }
    }
    // size() : 스택에 추가된 데이터의 크기를 리턴한다.
    public int size() {
        return listStack.size();
    }
    // peek() : 가장 나중에 추가된 데이터를 리턴한다.
    public Integer peek() {
        if (listStack.isEmpty()) return null;
        else {
            return listStack.get(listStack.size() - 1);
        }
    }
    // show() : 큐에 들어있는 모든 데이터를 String 타입으로 변환하여 리턴한다.
    public String show() {
        return listStack.toString();
    }
    // clear() : 큐에 들어 있는 모든 데이터를 삭제한다.
    public void clear() {
        listStack.clear();
    }

    public static void main(String[] args) {
        Stack stack = new Stack();

        stack.push(1);
        stack.push(2);
        stack.push(3);
        stack.push(4);
        stack.push(5);
        System.out.println(stack.show());
//      [1, 2, 3, 4, 5]

        stack.pop();
        stack.pop();
        stack.pop();
        System.out.println(stack.show());
//        [1, 2]
        stack.clear();
        System.out.println(stack.show());
//        []
    }
}
