package poc;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.yaml.snakeyaml.Yaml;

@RestController
public class ApiController {

  private static final Logger LOG = LogManager.getLogger(ApiController.class);

  @GetMapping("/health")
  public Map<String, String> health() {
    return Map.of("status", "ok");
  }

  @GetMapping("/greet")
  public Map<String, String> greet(
      @RequestParam(defaultValue = "world") String name,
      @RequestHeader(value = "User-Agent", defaultValue = "") String userAgent) {
    // VULN: Log4Shell. Untrusted input is logged by log4j-core 2.14.1 (JNDI lookups enabled)
    LOG.info("greet name={} ua={}", name, userAgent);
    return Map.of("message", "hello " + name);
  }

  @GetMapping("/ping")
  public Map<String, String> ping(@RequestParam(defaultValue = "127.0.0.1") String host)
      throws Exception {
    // VULN: OS command injection (user input in a shell string). Try ?host=127.0.0.1;id
    Process p = new ProcessBuilder("sh", "-c", "ping -c 1 " + host).redirectErrorStream(true).start();
    try (BufferedReader r =
        new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
      return Map.of("output", r.lines().collect(Collectors.joining("\n")));
    }
  }

  @PostMapping("/config")
  public Map<String, String> config(@RequestBody String body) {
    // VULN: unsafe YAML deserialization (SnakeYAML default constructor, CVE-2022-1471)
    Object parsed = new Yaml().load(body);
    return Map.of("parsed", String.valueOf(parsed));
  }

  @GetMapping("/fetch")
  public Map<String, Object> fetch(@RequestParam String url) throws Exception {
    // VULN: SSRF (server fetches any user-supplied URL)
    try (var in = new URL(url).openStream()) {
      return Map.of("length", in.readAllBytes().length);
    }
  }

  @GetMapping("/hash")
  public Map<String, String> hash(@RequestParam(defaultValue = "") String value) throws Exception {
    // VULN: weak hash algorithm (MD5)
    byte[] digest = MessageDigest.getInstance("MD5").digest(value.getBytes(StandardCharsets.UTF_8));
    return Map.of("md5", HexFormat.of().formatHex(digest));
  }
}
