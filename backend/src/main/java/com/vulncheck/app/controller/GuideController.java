package com.vulncheck.app.controller;

import com.vulncheck.app.repository.EcosystemRegistryRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequiredArgsConstructor
public class GuideController {

    private final EcosystemRegistryRepository ecosystemRegistryRepository;

    @GetMapping("/guide")
    public String guide() {
        return "guide";
    }

    @GetMapping("/guide/integrations")
    public String integrations(Model model) {
        model.addAttribute("ecosystems", ecosystemRegistryRepository.findAll());
        return "guide-integrations";
    }
}
