public class Tree {
    int count;

    public Tree() {
        count = 0;
    }

    public class Node {
        Object data;
        Node left;
        Node right;

        public Node(Object data) {
            this.data = data;
            left = null;
            right = null;
        }
        // void addLeft(Node node) : 좌측 노드에 연결 정보를 추가한다.
        public void addLeft(Node node) {
            left = node;
            count++;
        }
        // void addRight(Node node) : 우측 노드에 연결 정보를 추가한다.
        public void addRight(Node node) {
            right = node;
            count++;
        }
        // void deletedLeft() : 좌측 노드 연결 정보를 삭제한다.
        public void deleteLeft() {
            left = null;
            count--;
        }
        // void deleteRight() : 우측 노드 연결 정보를 삭제한다.
        public  void deleteRight() {
            right = null;
            count--;
        }
    }
    // Node addNode(Object data) : 노드를 새롭게 생성한다.
    public Node addNode(Object data) {
        Node n = new Node(data);
        return n;
    }

    // void preOrder(Node node) : 전위 순회
    public void preOrder(Node node) {
        if (node == null) {
            return;
        }

        System.out.print(node.data + "");
        preOrder(node.left);
        preOrder(node.right);
    }
    // void inOrder(Node node) : 중위 순회
    public void inOrder(Node node) {
        if (node == null) return;

        inOrder(node.left);
        System.out.print(node.data + "");
        inOrder(node.right);
    }
    // void postOrder(Node node) : 후위 순회
    public void postOrder(Node node) {
        if (node == null) return;

        postOrder(node.left);
        postOrder(node.right);
        System.out.print(node.data + "");
    }
    public static void main(String[] args) {
        Tree tree = new Tree();

        // 노드 생성
        Node node1 = tree.addNode(1);
        Node node2 = tree.addNode(2);
        Node node3 = tree.addNode(3);
        Node node4 = tree.addNode(4);
        Node node5 = tree.addNode(5);
        Node node6 = tree.addNode(6);
        Node node7 = tree.addNode(7);

        // 트리 연결관계 생성
        node1.addLeft(node2);
        node1.addRight(node3);
        node2.addLeft(node4);
        node2.addRight(node5);
        node3.addLeft(node6);
        node3.addRight(node7);
//             1
//          2     3
//        4  5   6  7

        // 순회
        tree.preOrder(node1);
        System.out.println();
//        1245367
        tree.inOrder(node1);
        System.out.println();
//        4251637
        tree.postOrder(node1);
        System.out.println();
//        4526731

        // 삭제
        node3.deleteLeft();
        node2.deleteRight();
//             1
//          2     3
//        4         7

        // 순회
        tree.preOrder(node1);
        System.out.println();
//        12437
        tree.inOrder(node1);
        System.out.println();
//        42137
        tree.postOrder(node1);
        System.out.println();
//        42731
    }
}

