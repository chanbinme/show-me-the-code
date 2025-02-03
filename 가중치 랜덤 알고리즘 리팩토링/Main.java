import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;

public class Main {

    private static final int COUPON_COUNT = 50;
    private static final int USER_COUNT = 1000000;
    private static final Random random = new Random();

    public static void main(String[] args) {
        Integer[] weights = generateWeights(COUPON_COUNT);

        // 기존 로직 성능 측정
        long linearStart = System.nanoTime();
        for (int i = 0; i < USER_COUNT; i++) {
            legacyWeightedChoice(weights);
        }
        long linearEnd = System.nanoTime();

        // 최적화된 로직 성능 측정
        long optimizedStart = System.nanoTime();
        for (int i = 0; i < USER_COUNT; i++) {
            optimizedWeightedChoice(weights);
        }
        long optimizedEnd = System.nanoTime();

        // 최적화된 로직 성능 측정(내림차순 정렬된 weights)
        Arrays.sort(weights, Collections.reverseOrder());
        long reverseOrderedOptimizedStart = System.nanoTime();
        for (int i = 0; i < USER_COUNT; i++) {
            optimizedWeightedChoice(weights);
        }
        long reverseOrderedOptimizedEnd = System.nanoTime();

        // 나노초를 초 단위로 변환하기 위해 1e9로 나눔 (1e9 = 10억)
        double legacyTime = (linearEnd - linearStart) / 1e9;
        double optimizedTime = (optimizedEnd - optimizedStart) / 1e9;
        double reverseOrderedOptimizedTime = (reverseOrderedOptimizedEnd - reverseOrderedOptimizedStart) / 1e9;
        double improvement = (legacyTime - optimizedTime) / legacyTime * 100;
        double reverseOrderedImprovement = (legacyTime - reverseOrderedOptimizedTime) / legacyTime * 100;

        System.out.printf("기존 로직 실행 시간: %.3f seconds%n", legacyTime);
        System.out.printf("최적화 로직 실행 시간: %.3f seconds%n", optimizedTime);
        System.out.printf("최적화 로직 실행 시간(내림차순): %.3f seconds%n", reverseOrderedOptimizedTime);
        System.out.printf("쿠폰 %d종, 발급 %d건 기준: %.2f%% 성능 향상%n", COUPON_COUNT, USER_COUNT, improvement);
        System.out.printf("쿠폰 %d종, 발급 %d건 기준(내림차순): %.2f%% 성능 향상%n", COUPON_COUNT, USER_COUNT, reverseOrderedImprovement);
    }

    // 기존 로직
    private static int legacyWeightedChoice(Integer[] weights) {
        List<Integer> totals = new ArrayList<>();
        int runningTotal = 0;
        for (int weight : weights) {
            runningTotal += weight;
            totals.add(runningTotal);
        }
        int randomWeight = random.nextInt(runningTotal);
        for (int i = 0; i < weights.length; i++) {
            if (randomWeight < totals.get(i)) {
                return i;
            }
        }
        return weights.length - 1;
    }

    // 최적화된 로직
    private static int optimizedWeightedChoice(Integer[] weights) {
        int totalWeight = 0;
        for (int weight : weights) {
            totalWeight += weight;
        }
        int randomWeight = random.nextInt(totalWeight);
        for (int i = 0; i < weights.length; i++) {
            randomWeight -= weights[i];
            if (randomWeight < 0) {
                return i;
            }
        }
        return weights.length - 1;
    }

    // 가중치 목록 생성
    private static Integer[] generateWeights(int count) {
        Integer[] weights = new Integer[count];
        for (int i = 0; i < count; i++) {
            weights[i] = random.nextInt(90) + 10; // 10 ~ 99
        }

        return weights;
    }
}
