package com.vulncheck.app.entity;

import java.io.Serializable;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

/** Composite key for {@link OsvAffectedVersion}. */
@EqualsAndHashCode
@NoArgsConstructor
@AllArgsConstructor
public class OsvAffectedVersionId implements Serializable {
    private Long affectedPackageId;
    private String version;
}
