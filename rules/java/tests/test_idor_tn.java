// True negative: scoped to current user (safe)
@RestController
public class InvoiceController {

    @Autowired
    private InvoiceRepository invoiceRepo;

    @GetMapping("/invoice/{id}")
    // ok: ez-spring-idor-path-variable
    public Invoice getInvoice(@PathVariable Long id, Principal principal) {
        Invoice invoice = invoiceRepo.findById(id).orElseThrow();
        if (invoice.getOwnerId().equals(principal.getName())) {
            return invoice;
        }
        throw new AccessDeniedException("Not your invoice");
    }
}
