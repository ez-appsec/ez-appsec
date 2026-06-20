// True positive: IDOR via direct findById without ownership check
@RestController
public class InvoiceController {

    @Autowired
    private InvoiceRepository invoiceRepo;

    @GetMapping("/invoice/{id}")
    public Invoice getInvoice(@PathVariable Long id) {
        // ruleid: ez-spring-idor-path-variable
        return invoiceRepo.findById(id).orElseThrow();
    }
}
