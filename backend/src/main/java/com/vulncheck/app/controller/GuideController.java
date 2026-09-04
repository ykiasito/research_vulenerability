package com.vulncheck.app.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Closed-mode backlog item 262 (Phase B6, senior-reviewer REVISE): {@link #integrations} used to
 * be DB-driven ({@code EcosystemRegistryRepository#findAll()}), but {@code ecosystem_registries}
 * is now kept permanently empty on the {@code closed-mode} branch (see {@code
 * R__closed_mode_strip.sql}) — rendering that data would have shown an empty table for a feature
 * that's actually still mostly working (9 of the 10 registry clients still serve Tier1 lookups
 * from their local mirror, see {@code docs/spec/closed-mode-plan.md} §3-2/§5-6), misleadingly
 * implying this deployment does no registry matching at all. {@code guide-integrations.html}'s
 * registry section is now a static list instead — no model attribute needed here anymore.
 *
 * <p>Maven Central is the one exception (senior-reviewer REVISE, second round): unlike the other
 * 9, it never got a closed-mode mirror ({@code docs/spec/closed-mode-plan.md} §5-4), so {@code
 * MavenCentralRegistryClient#lookup} is a permanent no-op on this branch. The guide page lists it
 * under "自動照合できない配布チャネル" instead of the working-registries table, and {@link
 * com.vulncheck.app.architecture.GuideIntegrationsEcosystemListTest} in the test tree pins this
 * split so it can't silently drift the next time a registry client is added, removed, or
 * no-op'd without the guide page being updated in the same change.
 */
@Controller
public class GuideController {

    @GetMapping("/guide")
    public String guide() {
        return "guide";
    }

    @GetMapping("/guide/integrations")
    public String integrations() {
        return "guide-integrations";
    }
}
