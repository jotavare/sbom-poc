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
  public static void main(String[] args) throws Exception {
    // The distroless image has no shell or curl: `java -jar app.jar healthcheck`
    // is the container's health check (like the Go and Rust apps).
    if (args.length == 1 && args[0].equals("healthcheck")) {
      var conn = (java.net.HttpURLConnection) new java.net.URL("http://127.0.0.1:8080/health").openConnection();
      conn.setConnectTimeout(2000);
      conn.setReadTimeout(2000);
      System.exit(conn.getResponseCode() == 200 ? 0 : 1);
    }
    SpringApplication.run(App.class, args);
  }
}
