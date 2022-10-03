import java.util.ArrayList;

public class Queue {
    private ArrayList<Integer> listQueue = new ArrayList<>();

    // add() : 큐에 데이터를 추가한다.
    public void add(Integer data) {
        listQueue.add(data);
    }
    // poll() : 가장 먼저 추가된 데이터를 삭제하고 삭제한 데이터를 반환한다.
    public Integer poll() {
        if (listQueue.isEmpty()) return null;
        else {
            return listQueue.remove(0);
        }
    }
    // size() : 큐에 추가도니 데이터의 크기를 리턴한다.
    public int size() {
        return listQueue.size();
    }
    // peek() : 큐에 가장 먼저 추가된 데이터를 리턴한다.
    public Integer peek() {
        return listQueue.get(0);
    }
    // show() : 큐에 들어있는 모든 데이터를 String 타입으로 변환하여 리턴한다.
    public String show() {
        return listQueue.toString();
    }
    // clear() : 큐에 들어 있는 모든 데이터를 삭제한다.
    public void clear() {
        listQueue.clear();
    }

    public static void main(String[] args) {
        Queue queue = new Queue();

        queue.add(1);
        queue.add(2);
        queue.add(3);
        queue.add(4);
        queue.add(5);
        System.out.println(queue.show());
//        [1, 2, 3, 4, 5]

        queue.poll();
        queue.poll();
        queue.poll();
        System.out.println(queue.show());
//        [4, 5]

        queue.clear();
        System.out.println(queue.show());
//        []
    }
}
