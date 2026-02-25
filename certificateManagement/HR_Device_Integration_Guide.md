    
    notification_service.send_email(
        to=employee_email,
        subject="Welcome Back - Access Restored",
        body="Your certificates and access have been restored."
    )
```

### 5.3 Role-Based Certificate Re-issuance

**Scenario: Engineering → Finance Transfer**

```python
def handle_department_transfer(employee_id, old_dept, new_dept, effective_date):
    """
    Re-issue certificates with new OU when employee changes departments
    """
    employee = hr_api.get_employee(employee_id)
    
    # Get current certificates
    current_certs = ca_database.query(
        "SELECT * FROM certificates "
        "WHERE employee_id = ? AND status = 'active'",
        (employee_id,)
    )
    
    for cert in current_certs:
        # Parse current subject DN
        subject_parts = parse_dn(cert['subject_dn'])
        
        # Update OU field
        subject_parts['OU'] = new_dept
        
        # Generate new CSR with updated subject
        new_csr = generate_csr(
            cn=employee['email'],
            o='Company Inc',
            ou=new_dept,
            email=employee['email']
        )
        
        # Issue new certificate
        new_cert = ca.issue_certificate(
            csr=new_csr,
            profile='user-certificate',
            validity_days=365
        )
        
        # Revoke old certificate
        ca.revoke_certificate(
            serial_number=cert['serial_number'],
            reason='affiliationChanged'
        )
        
        # Deliver new certificate to user
        deliver_certificate(
            employee_email=employee['email'],
            certificate=new_cert,
            delivery_method='email'  # or push via MDM
        )
```

---

## Part 6: Implementation Roadmap

### Phase 1: Foundation (Q1 2025)
- ✅ Deploy event-driven architecture (EventBridge/Pub-Sub)
- ✅ Implement HR system webhook integration (Workday → Trust Broker)
- ✅ Configure IdP event hooks (Okta/Azure AD → Trust Broker)
- ✅ Build certificate revocation engine
- ✅ Establish immutable audit logging

### Phase 2: MDM Integration (Q2 2025)
- ✅ Deploy SCEP endpoints on Trust Broker
- ✅ Integrate Jamf Pro for iOS/macOS certificate enrollment
- ✅ Integrate Microsoft Intune for Windows/Android
- ✅ Implement device certificate lifecycle automation
- ✅ Create BYOD vs Corporate device policies

### Phase 3: Automated Workflows (Q3 2025)
- ✅ Automated termination workflow (<5 min revocation SLA)
- ✅ Role change certificate re-issuance
- ✅ Leave of absence suspend/restore
- ✅ Contractor expiry auto-revocation
- ✅ Compliance alerting and reporting

### Phase 4: Monitoring & Compliance (Q4 2025)
- ✅ Real-time dashboards (Grafana)
- ✅ Prometheus alerts for delayed revocations
- ✅ Monthly compliance reports
- ✅ Quarterly security audits
- ✅ Disaster recovery drills

---

## Conclusion

Integrating your PKI architecture with HR systems and MDM platforms enables:

1. **Zero-Touch Automation**: Employee lifecycle events automatically trigger certificate operations
2. **Compliance**: <5 minute revocation SLA for terminated employees
3. **Audit Trail**: Immutable logs linking every certificate operation to HR events
4. **Mobile Security**: Seamless device enrollment with certificate-based authentication
5. **Risk Reduction**: No manual processes, no forgotten revocations
6. **Scalability**: Event-driven architecture handles 250K+ endpoints

The architecture maintains your core principles while adding enterprise-grade identity lifecycle management.

