import java.util.HashMap;
import java.util.Objects;
import lombok.Setter;

public class EqualsAndHashCodeTest {

    public static void main(String[] args) {
        // equals() 테스트
        Person person1 = new Person("김찬빈", 30);
        Person person2 = new Person("김찬빈", 30);
        Person person3 = new Person("홍길동", 25);

        System.out.println("equals() 테스트:");
        System.out.println("person1.equals(person2): " + person1.equals(person2));
        System.out.println("person1.equals(person3): " + person1.equals(person3));
        System.out.println("person1 == person2: " + (person1 == person2));

        // hashCode() 테스트
        System.out.println("\nhashCode() 테스트:");
        System.out.println("person1 hashCode: " + person1.hashCode());
        System.out.println("person2 hashCode: " + person2.hashCode());
        System.out.println("person3 hashCode: " + person3.hashCode());

        // HashMap을 사용한 테스트
        HashMap<Person, String> personMap = new HashMap<>();
        personMap.put(person1, "개발자");

        System.out.println("\nHashMap 테스트:");
        System.out.println("personMap.get(person2): " + personMap.get(person2));
        System.out.println("personMap.get(person3): " + personMap.get(person3));

        // 내용이 같은 새로운 Person 객체로 검색
        Person person4 = new Person("김찬빈", 30);
        System.out.println("personMap.get(person4): " + personMap.get(person4));
    }

    @Setter
    static class Person {

        private String name;
        private int age;

        public Person(String name, int age) {
            this.name = name;
            this.age = age;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Person person = (Person) o;
            return age == person.age && Objects.equals(name, person.name);
        }

        @Override
        public int hashCode() {
            return Objects.hash(name, age);
        }

        @Override
        public String toString() {
            return "Person{name='" + name + "', age=" + age + '}';
        }
    }
}
