# Sample Output

This is a portfolio-friendly example of how DNS Audit Tool findings can be interpreted.

## Audit Summary

| Finding | Count | Severity | Recommended Action |
| --- | ---: | --- | --- |
| Missing PTR records | 3 | Medium | Create or validate reverse lookup records. |
| PTR mismatch | 1 | High | Confirm the correct hostname and update DNS. |
| Potential stale records | 4 | Medium | Verify host ownership before cleanup. |
| Shared IP usage | 2 | Informational | Confirm whether shared usage is expected. |

## Example Finding

```csv
Zone,RecordName,RecordType,IPAddress,Finding,Severity,RecommendedAction
corp.example.local,ws-014,A,10.10.20.14,Missing PTR,Medium,Create or validate reverse lookup record
corp.example.local,old-printer,A,10.10.30.50,Potential stale record,Medium,Verify host ownership before removal
```

## Support Interpretation

The audit does not automatically prove a service outage. It highlights DNS records that need validation so support teams can reduce uncertainty during authentication, connectivity or application troubleshooting.
