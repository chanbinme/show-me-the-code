import lombok.extern.slf4j.Slf4j;

@Slf4j
public class LoggingComparisonTest {

    private static final int TEST_COUNT = 100;

    public static void main(String[] args) {
        // System.out.println 성능 테스트
        long startOut = System.nanoTime();
        for (int i = 0; i < TEST_COUNT; i++) {
            System.out.println("System.out message " + i);
        }

        double durationOut = (System.nanoTime() - startOut) / 1e9;

        // Log4j2 성능 테스트
        long startLog4j = System.nanoTime();
        for (int i = 0; i < TEST_COUNT; i++) {
            log.info("Log4j2 message {}", i);
        }

        double durationLog4j = (System.nanoTime() - startLog4j) / 1e9;

        System.out.printf("System.out.println 시간: %.3f sec%n", durationOut);
        System.out.printf("Log4j2 시간: %.3f sec%n", durationLog4j);
        System.out.printf("성능 차이: %.3f sec (%.1f%%)%n", durationOut - durationLog4j, ((durationOut - durationLog4j) / durationOut) * 100);
    }
}
