/// Data Governance Smart Contract for Walrus Security Suite
/// Implements decentralized data governance with privacy controls and compliance
module walrus_security::data_governance {
    use std::vector;
    use std::string::{Self, String};
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::event;
    use sui::clock::{Self, Clock};
    use sui::table::{Self, Table};

    // ======= Error Codes =======
    const E_NOT_AUTHORIZED: u64 = 1;
    const E_POLICY_NOT_FOUND: u64 = 2;
    const E_INVALID_RETENTION_PERIOD: u64 = 3;
    const E_CONSENT_EXPIRED: u64 = 4;
    const E_DATA_SUBJECT_NOT_FOUND: u64 = 5;
    const E_INVALID_PURPOSE: u64 = 6;

    // ======= Structs =======

    /// Main data governance registry
    struct DataGovernanceRegistry has key {
        id: UID,
        admin: address,
        policies: Table<String, DataPolicy>,
        data_subjects: Table<address, DataSubject>,
        consents: Table<String, ConsentRecord>,
        audit_logs: vector<AuditEvent>,
        compliance_frameworks: vector<String>,
    }

    /// Data processing policy
    struct DataPolicy has store {
        id: String,
        name: String,
        purpose: String,
        legal_basis: u8, // 1=Consent, 2=Contract, 3=LegalObligation, etc.
        retention_period_ms: u64,
        data_categories: vector<String>,
        allowed_processors: vector<address>,
        cross_border_transfer: bool,
        encryption_required: bool,
        anonymization_required: bool,
        created_at: u64,
        updated_at: u64,
        active: bool,
    }

    /// Data subject information
    struct DataSubject has store {
        id: address,
        pseudonym: String,
        preferences: PrivacyPreferences,
        consents: vector<String>, // Consent IDs
        data_categories: vector<String>,
        created_at: u64,
        last_updated: u64,
    }

    /// Privacy preferences for data subject
    struct PrivacyPreferences has store {
        share_data: bool,
        allow_profiling: bool,
        marketing_consent: bool,
        data_retention_days: u64,
        anonymization_preference: bool,
        contact_preferences: vector<String>,
    }

    /// Consent record
    struct ConsentRecord has store {
        id: String,
        data_subject: address,
        purpose: String,
        granted: bool,
        granted_at: u64,
        expires_at: u64,
        withdrawn_at: u64,
        legal_basis: String,
        metadata: vector<u8>,
        version: u64,
    }

    /// Access control list
    struct AccessControl has store {
        resource_id: String,
        owner: address,
        readers: vector<address>,
        writers: vector<address>,
        admins: vector<address>,
        public_read: bool,
        created_at: u64,
    }

    /// Data processing request
    struct ProcessingRequest has key {
        id: UID,
        requester: address,
        data_subject: address,
        purpose: String,
        policy_id: String,
        requested_data: vector<String>,
        legal_basis: u8,
        retention_period: u64,
        status: u8, // 1=Pending, 2=Approved, 3=Rejected, 4=Completed
        created_at: u64,
        approved_at: u64,
        expires_at: u64,
    }

    /// Audit event
    struct AuditEvent has store, drop, copy {
        event_id: String,
        actor: address,
        action: String,
        resource: String,
        data_subject: address,
        purpose: String,
        outcome: String,
        timestamp: u64,
        metadata: vector<u8>,
    }

    /// Data retention schedule
    struct RetentionSchedule has key {
        id: UID,
        data_category: String,
        retention_period_ms: u64,
        deletion_method: String,
        automated: bool,
        next_review: u64,
        responsible_party: address,
    }

    /// Compliance report
    struct ComplianceReport has key {
        id: UID,
        framework: String, // GDPR, CCPA, HIPAA, etc.
        period_start: u64,
        period_end: u64,
        status: String,
        issues: vector<ComplianceIssue>,
        recommendations: vector<String>,
        generated_by: address,
        generated_at: u64,
    }

    /// Compliance issue
    struct ComplianceIssue has store {
        rule: String,
        severity: String,
        description: String,
        affected_subjects: u64,
        recommendation: String,
        resolved: bool,
    }

    // ======= Events =======

    struct PolicyCreated has copy, drop {
        policy_id: String,
        creator: address,
        purpose: String,
    }

    struct ConsentGranted has copy, drop {
        consent_id: String,
        data_subject: address,
        purpose: String,
        granted_at: u64,
    }

    struct ConsentWithdrawn has copy, drop {
        consent_id: String,
        data_subject: address,
        purpose: String,
        withdrawn_at: u64,
    }

    struct DataProcessed has copy, drop {
        request_id: String,
        data_subject: address,
        processor: address,
        purpose: String,
        timestamp: u64,
    }

    struct DataErased has copy, drop {
        data_subject: address,
        categories: vector<String>,
        erased_by: address,
        timestamp: u64,
    }

    // ======= Public Functions =======

    /// Initialize the data governance registry
    public entry fun create_registry(ctx: &mut TxContext) {
        let registry = DataGovernanceRegistry {
            id: object::new(ctx),
            admin: tx_context::sender(ctx),
            policies: table::new(ctx),
            data_subjects: table::new(ctx),
            consents: table::new(ctx),
            audit_logs: vector::empty(),
            compliance_frameworks: vector::empty(),
        };

        transfer::share_object(registry);
    }

    /// Create a new data processing policy
    public entry fun create_policy(
        registry: &mut DataGovernanceRegistry,
        policy_id: String,
        name: String,
        purpose: String,
        legal_basis: u8,
        retention_period_ms: u64,
        data_categories: vector<String>,
        allowed_processors: vector<address>,
        cross_border_transfer: bool,
        encryption_required: bool,
        anonymization_required: bool,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        assert!(tx_context::sender(ctx) == registry.admin, E_NOT_AUTHORIZED);
        assert!(retention_period_ms > 0, E_INVALID_RETENTION_PERIOD);

        let now = clock::timestamp_ms(clock);

        let policy = DataPolicy {
            id: policy_id,
            name,
            purpose,
            legal_basis,
            retention_period_ms,
            data_categories,
            allowed_processors,
            cross_border_transfer,
            encryption_required,
            anonymization_required,
            created_at: now,
            updated_at: now,
            active: true,
        };

        table::add(&mut registry.policies, policy_id, policy);

        let audit_event = AuditEvent {
            event_id: generate_event_id(now, &policy_id),
            actor: tx_context::sender(ctx),
            action: string::utf8(b"POLICY_CREATED"),
            resource: policy_id,
            data_subject: @0x0,
            purpose,
            outcome: string::utf8(b"SUCCESS"),
            timestamp: now,
            metadata: vector::empty(),
        };

        vector::push_back(&mut registry.audit_logs, audit_event);

        event::emit(PolicyCreated {
            policy_id,
            creator: tx_context::sender(ctx),
            purpose,
        });
    }

    /// Register a data subject
    public entry fun register_data_subject(
        registry: &mut DataGovernanceRegistry,
        pseudonym: String,
        preferences: PrivacyPreferences,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let data_subject_addr = tx_context::sender(ctx);
        let now = clock::timestamp_ms(clock);

        let data_subject = DataSubject {
            id: data_subject_addr,
            pseudonym,
            preferences,
            consents: vector::empty(),
            data_categories: vector::empty(),
            created_at: now,
            last_updated: now,
        };

        table::add(&mut registry.data_subjects, data_subject_addr, data_subject);

        let audit_event = AuditEvent {
            event_id: generate_event_id(now, &string::utf8(b"SUBJECT_REGISTERED")),
            actor: data_subject_addr,
            action: string::utf8(b"SUBJECT_REGISTERED"),
            resource: string::utf8(b"DATA_SUBJECT"),
            data_subject: data_subject_addr,
            purpose: string::utf8(b"REGISTRATION"),
            outcome: string::utf8(b"SUCCESS"),
            timestamp: now,
            metadata: vector::empty(),
        };

        vector::push_back(&mut registry.audit_logs, audit_event);
    }

    /// Grant consent for data processing
    public entry fun grant_consent(
        registry: &mut DataGovernanceRegistry,
        consent_id: String,
        purpose: String,
        expires_at: u64,
        legal_basis: String,
        metadata: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let data_subject = tx_context::sender(ctx);
        let now = clock::timestamp_ms(clock);

        assert!(table::contains(&registry.data_subjects, data_subject), E_DATA_SUBJECT_NOT_FOUND);

        let consent = ConsentRecord {
            id: consent_id,
            data_subject,
            purpose,
            granted: true,
            granted_at: now,
            expires_at,
            withdrawn_at: 0,
            legal_basis,
            metadata,
            version: 1,
        };

        table::add(&mut registry.consents, consent_id, consent);

        // Update data subject's consent list
        let subject = table::borrow_mut(&mut registry.data_subjects, data_subject);
        vector::push_back(&mut subject.consents, consent_id);
        subject.last_updated = now;

        let audit_event = AuditEvent {
            event_id: generate_event_id(now, &consent_id),
            actor: data_subject,
            action: string::utf8(b"CONSENT_GRANTED"),
            resource: consent_id,
            data_subject,
            purpose,
            outcome: string::utf8(b"SUCCESS"),
            timestamp: now,
            metadata: vector::empty(),
        };

        vector::push_back(&mut registry.audit_logs, audit_event);

        event::emit(ConsentGranted {
            consent_id,
            data_subject,
            purpose,
            granted_at: now,
        });
    }

    /// Withdraw consent
    public entry fun withdraw_consent(
        registry: &mut DataGovernanceRegistry,
        consent_id: String,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let data_subject = tx_context::sender(ctx);
        let now = clock::timestamp_ms(clock);

        assert!(table::contains(&registry.consents, consent_id), E_CONSENT_EXPIRED);

        let consent = table::borrow_mut(&mut registry.consents, consent_id);
        assert!(consent.data_subject == data_subject, E_NOT_AUTHORIZED);

        consent.granted = false;
        consent.withdrawn_at = now;

        let audit_event = AuditEvent {
            event_id: generate_event_id(now, &consent_id),
            actor: data_subject,
            action: string::utf8(b"CONSENT_WITHDRAWN"),
            resource: consent_id,
            data_subject,
            purpose: consent.purpose,
            outcome: string::utf8(b"SUCCESS"),
            timestamp: now,
            metadata: vector::empty(),
        };

        vector::push_back(&mut registry.audit_logs, audit_event);

        event::emit(ConsentWithdrawn {
            consent_id,
            data_subject,
            purpose: consent.purpose,
            withdrawn_at: now,
        });
    }

    /// Request data processing
    public entry fun request_data_processing(
        registry: &mut DataGovernanceRegistry,
        data_subject: address,
        purpose: String,
        policy_id: String,
        requested_data: vector<String>,
        legal_basis: u8,
        retention_period: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let requester = tx_context::sender(ctx);
        let now = clock::timestamp_ms(clock);

        // Verify policy exists and requester is authorized
        assert!(table::contains(&registry.policies, policy_id), E_POLICY_NOT_FOUND);
        let policy = table::borrow(&registry.policies, policy_id);
        assert!(vector::contains(&policy.allowed_processors, &requester), E_NOT_AUTHORIZED);

        // Check consent if required
        if (legal_basis == 1) { // Consent-based
            validate_consent(registry, data_subject, purpose, now);
        };

        let request = ProcessingRequest {
            id: object::new(ctx),
            requester,
            data_subject,
            purpose,
            policy_id,
            requested_data,
            legal_basis,
            retention_period,
            status: 1, // Pending
            created_at: now,
            approved_at: 0,
            expires_at: now + retention_period,
        };

        let audit_event = AuditEvent {
            event_id: generate_event_id(now, &string::utf8(b"PROCESSING_REQUESTED")),
            actor: requester,
            action: string::utf8(b"PROCESSING_REQUESTED"),
            resource: string::utf8(b"DATA_PROCESSING"),
            data_subject,
            purpose,
            outcome: string::utf8(b"SUCCESS"),
            timestamp: now,
            metadata: vector::empty(),
        };

        vector::push_back(&mut registry.audit_logs, audit_event);

        transfer::transfer(request, requester);
    }

    /// Approve data processing request
    public entry fun approve_processing_request(
        registry: &mut DataGovernanceRegistry,
        request: &mut ProcessingRequest,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        assert!(tx_context::sender(ctx) == registry.admin, E_NOT_AUTHORIZED);
        assert!(request.status == 1, E_NOT_AUTHORIZED); // Must be pending

        let now = clock::timestamp_ms(clock);
        request.status = 2; // Approved
        request.approved_at = now;

        let audit_event = AuditEvent {
            event_id: generate_event_id(now, &string::utf8(b"PROCESSING_APPROVED")),
            actor: tx_context::sender(ctx),
            action: string::utf8(b"PROCESSING_APPROVED"),
            resource: string::utf8(b"DATA_PROCESSING"),
            data_subject: request.data_subject,
            purpose: request.purpose,
            outcome: string::utf8(b"SUCCESS"),
            timestamp: now,
            metadata: vector::empty(),
        };

        vector::push_back(&mut registry.audit_logs, audit_event);

        event::emit(DataProcessed {
            request_id: generate_event_id(now, &request.purpose),
            data_subject: request.data_subject,
            processor: request.requester,
            purpose: request.purpose,
            timestamp: now,
        });
    }

    /// Exercise right to be forgotten
    public entry fun right_to_be_forgotten(
        registry: &mut DataGovernanceRegistry,
        categories: vector<String>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let data_subject = tx_context::sender(ctx);
        let now = clock::timestamp_ms(clock);

        assert!(table::contains(&registry.data_subjects, data_subject), E_DATA_SUBJECT_NOT_FOUND);

        // Mark for erasure (implementation would trigger actual deletion)
        let subject = table::borrow_mut(&mut registry.data_subjects, data_subject);
        subject.last_updated = now;

        let audit_event = AuditEvent {
            event_id: generate_event_id(now, &string::utf8(b"RIGHT_TO_BE_FORGOTTEN")),
            actor: data_subject,
            action: string::utf8(b"DATA_ERASURE_REQUESTED"),
            resource: string::utf8(b"DATA_SUBJECT"),
            data_subject,
            purpose: string::utf8(b"RIGHT_TO_BE_FORGOTTEN"),
            outcome: string::utf8(b"SUCCESS"),
            timestamp: now,
            metadata: vector::empty(),
        };

        vector::push_back(&mut registry.audit_logs, audit_event);

        event::emit(DataErased {
            data_subject,
            categories,
            erased_by: data_subject,
            timestamp: now,
        });
    }

    /// Generate compliance report
    public entry fun generate_compliance_report(
        registry: &DataGovernanceRegistry,
        framework: String,
        period_start: u64,
        period_end: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        assert!(tx_context::sender(ctx) == registry.admin, E_NOT_AUTHORIZED);

        let now = clock::timestamp_ms(clock);
        let issues = analyze_compliance(registry, &framework, period_start, period_end);

        let report = ComplianceReport {
            id: object::new(ctx),
            framework,
            period_start,
            period_end,
            status: if (vector::is_empty(&issues)) {
                string::utf8(b"COMPLIANT")
            } else {
                string::utf8(b"NON_COMPLIANT")
            },
            issues,
            recommendations: generate_recommendations(&framework),
            generated_by: tx_context::sender(ctx),
            generated_at: now,
        };

        transfer::transfer(report, tx_context::sender(ctx));
    }

    // ======= Helper Functions =======

    fun validate_consent(
        registry: &DataGovernanceRegistry,
        data_subject: address,
        purpose: String,
        current_time: u64
    ) {
        let subject = table::borrow(&registry.data_subjects, data_subject);
        let consent_ids = &subject.consents;

        let i = 0;
        let found_valid = false;

        while (i < vector::length(consent_ids)) {
            let consent_id = vector::borrow(consent_ids, i);
            let consent = table::borrow(&registry.consents, *consent_id);

            if (consent.purpose == purpose &&
                consent.granted &&
                (consent.expires_at == 0 || consent.expires_at > current_time)) {
                found_valid = true;
                break
            };

            i = i + 1;
        };

        assert!(found_valid, E_CONSENT_EXPIRED);
    }

    fun generate_event_id(timestamp: u64, suffix: &String): String {
        // Simplified event ID generation
        let timestamp_str = string::utf8(b"");
        string::append(&mut timestamp_str, *suffix);
        timestamp_str
    }

    fun analyze_compliance(
        _registry: &DataGovernanceRegistry,
        _framework: &String,
        _period_start: u64,
        _period_end: u64
    ): vector<ComplianceIssue> {
        // Simplified compliance analysis
        vector::empty<ComplianceIssue>()
    }

    fun generate_recommendations(_framework: &String): vector<String> {
        let recommendations = vector::empty<String>();
        vector::push_back(&mut recommendations, string::utf8(b"Implement regular data audits"));
        vector::push_back(&mut recommendations, string::utf8(b"Enhance consent management"));
        vector::push_back(&mut recommendations, string::utf8(b"Improve data retention policies"));
        recommendations
    }

    // ======= View Functions =======

    public fun get_policy(
        registry: &DataGovernanceRegistry,
        policy_id: String
    ): &DataPolicy {
        table::borrow(&registry.policies, policy_id)
    }

    public fun get_data_subject(
        registry: &DataGovernanceRegistry,
        subject_id: address
    ): &DataSubject {
        table::borrow(&registry.data_subjects, subject_id)
    }

    public fun get_consent(
        registry: &DataGovernanceRegistry,
        consent_id: String
    ): &ConsentRecord {
        table::borrow(&registry.consents, consent_id)
    }

    public fun is_valid_consent(
        registry: &DataGovernanceRegistry,
        data_subject: address,
        purpose: String,
        current_time: u64
    ): bool {
        if (!table::contains(&registry.data_subjects, data_subject)) {
            return false
        };

        let subject = table::borrow(&registry.data_subjects, data_subject);
        let consent_ids = &subject.consents;

        let i = 0;
        while (i < vector::length(consent_ids)) {
            let consent_id = vector::borrow(consent_ids, i);
            let consent = table::borrow(&registry.consents, *consent_id);

            if (consent.purpose == purpose &&
                consent.granted &&
                (consent.expires_at == 0 || consent.expires_at > current_time)) {
                return true
            };

            i = i + 1;
        };

        false
    }
}