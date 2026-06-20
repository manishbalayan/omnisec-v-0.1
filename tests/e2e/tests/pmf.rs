// PMF Preparation — Phase 10
//
// Captures the Product-Market Fit research artifacts for Omnisec:
// ICP definition, design partner profile, customer interview questions,
// top metrics, feature usage analysis, and pricing hypotheses.
//
// Run: cargo test -p omnisec-e2e --test pmf -- --nocapture

#[test]
fn pmf_ideal_customer_profile() {
    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║              IDEAL CUSTOMER PROFILE (ICP)                        ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    let icp = [
        ("Company size",    "50–2000 employees; Series B or later; engineering-led"),
        ("Industry",        "Fintech, Healthcare, Legal, Defense, GovTech — regulated verticals"),
        ("AI posture",      "Running autonomous AI agents in production or staging within 6 months"),
        ("Pain point",      "Board / compliance team demanding auditability of AI agent actions"),
        ("Tech stack",      "Linux workloads; Kubernetes or bare metal; own infrastructure"),
        ("Buyer",           "CISO or VP Engineering — budget owner for runtime security tooling"),
        ("Champion",        "Staff/Principal Engineer — evaluates and advocates for the tool"),
        ("Red flag",        "Fully managed cloud AI with zero self-hosted infra — not our wedge"),
        ("Red flag",        "Organizations that use only one AI vendor — low cross-provider value"),
    ];

    for (key, value) in &icp {
        println!("  {:20} {}", format!("{}:", key), value);
    }

    println!();
    println!("  WHY NOW:");
    println!("    AI agent deployments are outpacing audit tooling. Regulators (EU AI Act,");
    println!("    NIST AI RMF, SEC) are beginning to require runtime behavioral controls for");
    println!("    autonomous systems. The 12-month window before enforcement tooling becomes");
    println!("    commoditized is the land-and-expand opportunity.");
}

#[test]
fn pmf_design_partner_profile() {
    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║              DESIGN PARTNER PROFILE                              ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    println!("  WHAT MAKES A GOOD DESIGN PARTNER:");
    let criteria = [
        "Has ≥ 2 AI agents in production or active staging environment",
        "Experienced a security incident or compliance audit in the last 12 months",
        "Willing to run Omnisec in OMNISEC_SAFE_MODE=1 for 30 days first",
        "Has a dedicated engineer who can instrument the integration",
        "Will share anonymized incident logs and false positive rates",
        "Will provide written feedback after 60 days of usage",
        "Senior leader sponsors the evaluation (not just an engineer experiment)",
    ];
    for c in &criteria {
        println!("    + {}", c);
    }

    println!();
    println!("  DESIGN PARTNER ONBOARDING SEQUENCE:");
    let steps = [
        ("Day 0",   "Sign NDA + Design Partner Agreement; share integration guide"),
        ("Day 1",   "Deploy in SAFE_MODE: observe decisions, zero enforcement"),
        ("Day 7",   "Review first week's recommendations; calibrate thresholds"),
        ("Day 14",  "Enable RECOMMENDATION_ONLY: decisions logged for human approval"),
        ("Day 30",  "30-day review call: false positive rate, incident coverage, UX"),
        ("Day 45",  "Enable selective enforcement on highest-risk agents"),
        ("Day 60",  "Full deployment decision; negotiate commercial terms"),
    ];
    for (day, action) in &steps {
        println!("    {:8} {}", day, action);
    }
}

#[test]
fn pmf_customer_interview_questions() {
    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║              CUSTOMER INTERVIEW QUESTIONS (20)                   ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    let questions = [
        // Discovery
        ("Discovery",   "1",  "Walk me through how your AI agents are deployed in production today."),
        ("Discovery",   "2",  "What's the most unexpected thing an AI agent has done in your environment?"),
        ("Discovery",   "3",  "How do you currently know if an AI agent is misbehaving?"),
        ("Discovery",   "4",  "Has an AI agent ever caused an incident? Walk me through what happened."),
        ("Discovery",   "5",  "What does your compliance team ask about AI agents? What can't you answer?"),

        // Pain intensity
        ("Pain",        "6",  "How long does it take to investigate an AI agent anomaly today?"),
        ("Pain",        "7",  "If an AI agent started exfiltrating data right now, how long until you knew?"),
        ("Pain",        "8",  "What would you have to do manually that Omnisec would automate?"),
        ("Pain",        "9",  "What's the cost of a single AI agent security incident for you? (Regulatory, reputational, operational)"),
        ("Pain",        "10", "Are you being asked by your board or auditors to prove AI agent controls exist?"),

        // Current solutions
        ("Solutions",   "11", "What tools do you use today to monitor AI agent behavior?"),
        ("Solutions",   "12", "Have you evaluated any AI agent security products? What made you say no?"),
        ("Solutions",   "13", "What would make you rip out Omnisec after 90 days?"),

        // Value & fit
        ("Value",       "14", "Which feature would you pay for on day 1? (runtime blocking, anomaly detection, audit log, cost observability)"),
        ("Value",       "15", "If Omnisec blocked a legitimate AI agent action, what would happen to you? How bad is a false positive?"),
        ("Value",       "16", "How many AI agents are you running? How many do you expect in 12 months?"),
        ("Value",       "17", "Would you prefer SaaS or self-hosted? What drives that?"),

        // Pricing
        ("Pricing",     "18", "What budget category does AI agent security fall into? (Security tooling, AI ops, platform engineering)"),
        ("Pricing",     "19", "What are you paying per-agent per-month for your current monitoring stack?"),
        ("Pricing",     "20", "At what price point does Omnisec become a no-brainer vs. a committee decision?"),
    ];

    let mut current_category = "";
    for (category, num, question) in &questions {
        if *category != current_category {
            println!("  ── {} ──────────────────────────────────────", category);
            current_category = category;
        }
        println!("  {}. {}", num, question);
    }

    assert_eq!(questions.len(), 20, "Must have exactly 20 interview questions");
}

#[test]
fn pmf_top_metrics() {
    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║              TOP 10 PMF METRICS                                  ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    let metrics = [
        // Engagement
        ("Engagement",   "Daily Active Agents Monitored",
         "Agents observed by Omnisec per day",
         "Growing week-over-week — shows adoption depth"),
        ("Engagement",   "Time to First Detection (TTFD)",
         "Minutes from agent anomaly start to Omnisec incident creation",
         "Target < 2 minutes; < 30 seconds for critical severity"),
        ("Engagement",   "False Positive Rate",
         "Enforcement actions later overridden by operator as false positive",
         "Target < 5%; > 15% indicates threshold miscalibration"),

        // Retention
        ("Retention",    "7/30/90-day Retention",
         "% of design partners still running Omnisec after 7, 30, 90 days",
         "North Star: 90-day retention > 70% signals product-market fit"),
        ("Retention",    "Safe Mode → Full Enforcement Conversion",
         "% of partners who progress from SAFE_MODE to live enforcement",
         "Target: 50% convert within 30 days; measures trust building"),

        // Expansion
        ("Expansion",    "Agents per Account Growth",
         "Average agent count per customer, measured monthly",
         "Strong PMF: customers add more agents to Omnisec, not fewer"),
        ("Expansion",    "Feature Breadth Score",
         "Average # of features used per account (cache, cost, recommendations, enforcement)",
         "Target: ≥ 3 features active at 60 days — measures stickiness"),

        // Business
        ("Business",     "Net Revenue Retention (NRR)",
         "Revenue from cohort at month 12 / revenue at month 1",
         "Target: > 110%; indicates expansion within accounts"),
        ("Business",     "Time to Value (TTV)",
         "Days from sign-up to first meaningful detection (real incident caught)",
         "Target: < 7 days; long TTV predicts churn"),
        ("Business",     "Sean Ellis PMF Score",
         "% of users who would be 'very disappointed' if Omnisec disappeared",
         "PMF threshold: > 40% very disappointed; measure at 60-day check-in"),
    ];

    let mut current_category = "";
    let mut i = 1;
    for (category, name, description, signal) in &metrics {
        if *category != current_category {
            println!("  ── {} ──────────────────────────────────────", category);
            current_category = category;
        }
        println!("  {}. {}", i, name);
        println!("     Description: {}", description);
        println!("     Signal:      {}", signal);
        println!();
        i += 1;
    }

    assert_eq!(metrics.len(), 10, "Must track exactly 10 PMF metrics");
}

#[test]
fn pmf_feature_usage_analysis() {
    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║              FEATURE USAGE ANALYSIS                              ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    #[derive(Debug)]
    struct Feature {
        name: &'static str,
        predicted_adoption: &'static str,
        value_signal: &'static str,
        current_state: &'static str,
        priority: &'static str,
    }

    let features = [
        Feature {
            name: "Anomaly Detection + Incident Creation",
            predicted_adoption: "HIGH — core value proposition",
            value_signal: "First detection of real incident within trial period",
            current_state: "Built: 9 anomaly types, correlation engine, 17 tests pass",
            priority: "P0 — ship as-is",
        },
        Feature {
            name: "nftables Runtime Blocking",
            predicted_adoption: "MEDIUM — high value, high fear of false positives",
            value_signal: "Design partner enables full enforcement (exits SAFE_MODE)",
            current_state: "Built: domain block with DNS resolution, auto-recovery TTL",
            priority: "P0 — ship with safe mode default",
        },
        Feature {
            name: "Response Cache (Proxy Layer)",
            predicted_adoption: "HIGH — immediate cost reduction, low risk",
            value_signal: "Cache hit rate > 20% within first week",
            current_state: "Built: SHA-256 key, Redis backend, /proxy/cache/metrics endpoint",
            priority: "P0 — strong standalone value even without enforcement",
        },
        Feature {
            name: "Cost Observability Dashboard",
            predicted_adoption: "HIGH — CFO and FinOps teams want this independently",
            value_signal: "Customer shares cost dashboard with finance team",
            current_state: "Built: microdollar storage, daily rollup, by-agent breakdown",
            priority: "P0 — potential land-and-expand hook",
        },
        Feature {
            name: "Model Recommendations (Human-Approval)",
            predicted_adoption: "MEDIUM — valuable but slow adoption without UX",
            value_signal: "First approved recommendation saves measurable cost",
            current_state: "Built: complexity scoring, approve/reject API, no auto-routing",
            priority: "P1 — needs web UI for approval workflow",
        },
        Feature {
            name: "omnisec doctor",
            predicted_adoption: "HIGH during onboarding, LOW after",
            value_signal: "Reduces time-to-deploy for new design partners",
            current_state: "Built: 10 checks, TCP probes, Linux capability detection",
            priority: "P1 — critical for self-service onboarding",
        },
        Feature {
            name: "omnisec support-bundle",
            predicted_adoption: "LOW frequency, HIGH value when needed",
            value_signal: "Support ticket resolution time reduction",
            current_state: "Built: tar.gz with logs, env (redacted), nftables, processes",
            priority: "P1 — reduces support burden",
        },
        Feature {
            name: "Design Partner Mode (SAFE_MODE)",
            predicted_adoption: "UNIVERSAL — every new customer starts here",
            value_signal: "Customer progresses to RECOMMENDATION_ONLY within 14 days",
            current_state: "Built: SAFE_MODE, RECOMMENDATION_ONLY, VERBOSE env flags",
            priority: "P0 — required for trust-building sales motion",
        },
    ];

    for (i, f) in features.iter().enumerate() {
        println!("  {}. {}", i + 1, f.name);
        println!("     Adoption:   {}", f.predicted_adoption);
        println!("     Signal:     {}", f.value_signal);
        println!("     Status:     {}", f.current_state);
        println!("     Priority:   {}", f.priority);
        println!();
    }
}

#[test]
fn pmf_pricing_hypotheses() {
    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║              PRICING HYPOTHESES                                  ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    println!("  PRICING MODEL: Per-agent, per-month subscription");
    println!("  Rationale: Aligns with customer growth; expands as AI adoption scales.");
    println!();

    let tiers = [
        ("Starter",     "$29/agent/mo",  "≤ 10 agents",   "Anomaly detection, audit log, doctor, support-bundle"),
        ("Professional","$59/agent/mo",  "11–100 agents",  "Starter + enforcement, cost observability, cache proxy"),
        ("Enterprise",  "$99/agent/mo",  "101+ agents",    "Professional + recommendations, SLA, SSO, custom policies"),
        ("Self-Hosted",  "Contact us",   "Any",            "Full feature set; annual license; air-gap support"),
    ];

    println!("  {:14} {:15} {:15} {}", "Tier", "Price", "Agent Count", "Includes");
    println!("  {}", "─".repeat(80));
    for (tier, price, agents, features) in &tiers {
        println!("  {:14} {:15} {:15} {}", tier, price, agents, features);
    }

    println!();
    println!("  VALIDATION HYPOTHESES:");
    let hypotheses = [
        "H1: Customers pay for anomaly detection alone at $29/agent — validates core value",
        "H2: Cache proxy ROI (cost savings > subscription cost) makes Professional self-funding",
        "H3: Enterprise customers need SSO + custom policies before signing (infosec requirement)",
        "H4: Self-hosted is required for fintech/healthcare/defense — not just preferred",
        "H5: Per-agent pricing creates land-and-expand: start with 5 agents, grow to 50",
    ];
    for h in &hypotheses {
        println!("    {}", h);
    }

    println!();
    println!("  COMPETITIVE ANCHORS:");
    println!("    Datadog APM:        ~$31/host/mo  (observability only, no enforcement)");
    println!("    Aqua Security:      ~$50/node/mo  (container security, not AI-specific)");
    println!("    Omnisec advantage:  AI-agent-specific + enforcement + cost obs in one tool");

    // Sanity check the pricing logic
    let starter_cost = 29u32;
    let professional_cost = 59u32;
    let enterprise_cost = 99u32;

    assert!(professional_cost > starter_cost, "Professional must cost more than Starter");
    assert!(enterprise_cost > professional_cost, "Enterprise must cost more than Professional");
    assert!(enterprise_cost < 200, "Enterprise < $200/agent to remain competitive");
}
