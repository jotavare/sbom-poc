package poc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Deliberately vulnerable Spring Boot API for the DevSecOps PoC.
 *
 * <p>WARNING: this app contains intentional security flaws so that scanners have something to
 * find. Never expose it to a network you don't control. Each planted flaw is tagged {@code VULN:}.
 */
@SpringBootApplication
public class App {
  public static void main(String[] args) {
    SpringApplication.run(App.class, args);
  }
}
