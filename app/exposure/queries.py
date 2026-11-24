from sqlalchemy import RowMapping, text
from sqlalchemy.orm import Session

_EXPOSURE_SUMMARY = text(
    """
    WITH latest_versions AS (
        SELECT
            pv.id,
            pv.product_id,
            pv.version,
            ROW_NUMBER() OVER (
                PARTITION BY pv.product_id
                ORDER BY pv.sbom_uploaded_at DESC, pv.id DESC
            ) AS position
        FROM product_versions AS pv
        JOIN products AS p ON p.id = pv.product_id
        WHERE p.organization_id = :organization_id
          AND pv.sbom_uploaded_at IS NOT NULL
    ),
    open_findings AS (
        SELECT f.product_version_id, v.severity, v.is_known_exploited
        FROM findings AS f
        JOIN vulnerabilities AS v ON v.id = f.vulnerability_id
        WHERE f.status IN ('new', 'investigating', 'affected')
    )
    SELECT
        p.id AS product_id,
        p.name AS product_name,
        lv.version AS latest_version,
        count(o.product_version_id) AS open_findings,
        count(o.product_version_id) FILTER (WHERE o.severity = 'critical') AS open_critical,
        count(o.product_version_id) FILTER (WHERE o.severity = 'high') AS open_high,
        count(o.product_version_id) FILTER (WHERE o.is_known_exploited) AS open_known_exploited
    FROM products AS p
    LEFT JOIN latest_versions AS lv ON lv.product_id = p.id AND lv.position = 1
    LEFT JOIN open_findings AS o ON o.product_version_id = lv.id
    WHERE p.organization_id = :organization_id
    GROUP BY p.id, p.name, lv.version
    ORDER BY open_known_exploited DESC, open_critical DESC, open_findings DESC, p.name
    """
)


def exposure_summary(session: Session, organization_id: int) -> list[RowMapping]:
    """Return one row per product: its latest uploaded version and its open findings."""
    result = session.execute(_EXPOSURE_SUMMARY, {"organization_id": organization_id})
    return list(result.mappings())
