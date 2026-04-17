UPDATE cves
SET trending_score = ROUND((
  COALESCE(cvss_base_score, 0) * 10
  + CASE severity
      WHEN 'CRITICAL' THEN 60
      WHEN 'HIGH' THEN 48
      WHEN 'MEDIUM' THEN 36
      WHEN 'LOW' THEN 24
      WHEN 'NONE' THEN 12
      ELSE 0
    END
  + CASE WHEN has_kev THEN 18 ELSE 0 END
  + GREATEST(0, 30 - LEAST(30, EXTRACT(DAY FROM (NOW() - published_at))))
)::numeric, 2);
