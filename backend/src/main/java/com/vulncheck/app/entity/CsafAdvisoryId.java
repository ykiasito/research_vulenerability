package com.vulncheck.app.entity;

import java.io.Serializable;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

/** Composite key for {@link CsafAdvisory} — CSAF {@code tracking.id} is only unique within a
 *  vendor's own namespace, not globally (see V17's migration comment). */
@EqualsAndHashCode
@NoArgsConstructor
@AllArgsConstructor
public class CsafAdvisoryId implements Serializable {
    private String vendor;
    private String trackingId;
}
