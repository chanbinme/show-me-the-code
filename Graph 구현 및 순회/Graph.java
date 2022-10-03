import java.util.*;
import java.util.Queue;
import java.util.Stack;

public class Graph {
    public static void main(String[] args) {
        int[][] edges = new int[][]{
                {0, 1},
                {2, 3},
                {3, 4},
                {3, 5},
        };
        // TODO:
        // 더이상 연결된 정점이 없으면 컴포넌트 1개로 친다.

        // edges 배열에서 가장 높은 수 max를 구함
        int max = 0;
        for (int i = 0; i < edges.length; i++) {
            for (int j = 0; j < edges[i].length; j++) {
                if (edges[i][j] > max) max = edges[i][j];
            }
        }
        // max + 1 크기의 2차원 배열 생성
        int[][] vertex = new int[max + 1][max + 1];
        // 2차원 배열에 0 채우기
        for (int i = 0; i < vertex.length; i++) {
            for (int j = 0; j < vertex.length; j++) {
                vertex[i][j] = 0;
            }
        }
        // edges를 기반으로 값 추가. 무향이기 때문에 [from][to] && [to][from] 모두 1
        for (int i = 0; i < edges.length; i++) {
            vertex[edges[i][0]][edges[i][1]] = 1;
            vertex[edges[i][1]][edges[i][0]] = 1;
        }

        Graph dfs = new Graph();
        Graph bfs = new Graph();

        System.out.println(dfs.DFS(vertex));
        System.out.println(bfs.BFS(vertex));
    }

    // BFS 순회
    public int BFS(int[][] vertex) {
        // 방문 여부 확인을 위한 배열 생성
        boolean[] isVisited = new boolean[vertex.length];
        // 큐 선언
        Queue<Integer> q = new LinkedList<>();
        // 0부터 순회하기위해서 큐에 0 저장
        q.add(0);
        // 컴포넌트가 몇 개인지 저장할 count
        int count = 0;
        // 큐가 빌 때까지 반복
        while (!q.isEmpty()) {
            // from에 큐 첫 번째 요소 저장 + 큐에서 삭제
            int from = q.poll();
            // from 행을 순회하기 위한 반복문
            for (int i = 0; i < vertex.length; i++) {
                // 간선이 있으면서 방문한적이 없으면
                if (vertex[from][i] == 1 && isVisited[i] == false) {
                    // 큐에 i 저장~
                    q.add(i);
                    // i 방문 표시~
                    isVisited[i] = true;
                }
            }
            // q가 비어버리면?
            if (q.isEmpty()) {
                // count + 1!
                count++;
                // 아직 방문하지 않은 정점을 찾아보자
                for (int j = 0; j < isVisited.length; j++) {
                    // 있으면?
                    if (isVisited[j] == false) {
                        // 큐에 넣고
                        q.add(j);
                        // 방문 표시!
                        isVisited[j] = true;
                        // 반복문 중단!
                        break;
                    }
                }
            }
        }
        return count;
    }

    public int DFS(int[][] vertex) {
        Stack<Integer> stack = new Stack<>();
        boolean[] isVisited = new boolean[vertex.length];
        // 개수 세는 용
        int count = 0;
        stack.push(0);
        while (!stack.isEmpty()) {
            int from = stack.pop();

            for (int i = 0; i < vertex.length; i++) {
                if (vertex[from][i] == 1 && isVisited[i] == false) {
                    stack.push(i);
                    isVisited[i] = true;
                }
            }

            if (stack.isEmpty()) {
                count++;
                for (int j = 0; j < isVisited.length; j++) {
                    if (isVisited[j] == false) {
                        stack.push(j);
                        break;
                    }
                }
            }
        }
        return count;
    }
}
