package com.guettafa.JwtBackend.customer;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/customers")
@RequiredArgsConstructor
public class CustomerController {

    private final CustomerService customerService;

    @GetMapping("/{email}")
    public ResponseEntity<Customer> getCustomerWithEmail(@PathVariable String email) {
        return ResponseEntity.ok(customerService.getByEmail(email));
    }

    @GetMapping("/admin")
    public ResponseEntity<String> getAccess() {
        return ResponseEntity.ok("This is an endpoint that can only be used by admins");
    }


}
