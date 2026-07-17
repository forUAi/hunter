package example;

import java.nio.file.Files;
import java.nio.file.Paths;
import org.slf4j.Logger;
import org.springframework.web.bind.annotation.*;

@RestController
class DashboardController {
  private final Logger logger = null;
  private final Cluster cluster = null;

  @PostMapping("/accounts/{accountId}/payments/{paymentId}")
  @Transactional
  public void capturePayment(@PathVariable String accountId,
                             @PathVariable String paymentId,
                             @RequestBody PaymentRequest request) throws Exception {
    var payment = repository.findById(paymentId);
    cluster.query("UPDATE payments SET amount = " + request.amount());
    ledger.append(paymentId, request.amount());
    auditRepository.save(new AuditEvent(paymentId));
    logger.info("captured payment " + paymentId);
  }

  @DeleteMapping("/exports/{fileName}")
  public void deleteExport(@PathVariable String fileName) throws Exception {
    Files.delete(Paths.get("exports", fileName));
  }
}
