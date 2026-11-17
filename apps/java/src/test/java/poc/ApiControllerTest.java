package poc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(ApiController.class)
class ApiControllerTest {

  @Autowired private MockMvc mvc;

  @Test
  void health() throws Exception {
    mvc.perform(get("/health")).andExpect(status().isOk()).andExpect(jsonPath("$.status").value("ok"));
  }

  @Test
  void hashIsMd5() throws Exception {
    mvc.perform(get("/hash").param("value", "abc"))
        .andExpect(jsonPath("$.md5").value("900150983cd24fb0d6963f7d28e17f72"));
  }

  @Test
  void greet() throws Exception {
    mvc.perform(get("/greet").param("name", "alice"))
        .andExpect(jsonPath("$.message").value("hello alice"));
  }
}
