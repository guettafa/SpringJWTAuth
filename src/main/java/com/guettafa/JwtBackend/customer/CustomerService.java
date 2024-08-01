package com.guettafa.JwtBackend.customer;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomerService {

    private final CustomerRepository customerRepository;

    public Customer getByEmail(String email) {
        return customerRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("There's no User associated with this email"));
    }

    public Customer saveCustomer(Customer customer) {
        return customerRepository.save(customer);
    }

}
