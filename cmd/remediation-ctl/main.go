package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"autonomous-remediation-engine/internal/ai"
	"autonomous-remediation-engine/internal/audit"
	"autonomous-remediation-engine/internal/damping"
	"autonomous-remediation-engine/internal/engine"
	"autonomous-remediation-engine/internal/model"
	"autonomous-remediation-engine/internal/rollback"
	"autonomous-remediation-engine/internal/runbooks"
)

func defaultCatalog() []*model.Runbook {
	return runbooks.DefaultCatalog()
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcommand := os.Args[1]
	switch subcommand {
	case "run":
		handleRun(os.Args[2:])
	case "triage":
		handleTriage(os.Args[2:])
	case "verify-audit":
		handleVerifyAudit(os.Args[2:])
	case "status":
		handleStatus(os.Args[2:])
	case "list-runbooks":
		handleListRunbooks(os.Args[2:])
	case "damping-status":
		handleDampingStatus(os.Args[2:])
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %q\n\n", subcommand)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Autonomous Remediation Engine Controller (remediation-ctl)")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  remediation-ctl run --runbook=<id> --resource=<res> [--audit-log=<path>] [--lock-dir=<dir>] [--journal-dir=<dir>] [--damping-file=<path>]")
	fmt.Println("  remediation-ctl triage --incident=<text|file> [--execute] [--api-key=<key>] [--base-url=<url>] [--model=<model>]")
	fmt.Println("  remediation-ctl verify-audit --file=<path>")
	fmt.Println("  remediation-ctl status [--journal-dir=<dir>]")
	fmt.Println("  remediation-ctl list-runbooks")
	fmt.Println("  remediation-ctl damping-status [--damping-file=<path>] [--resource=<res>]")
}

func handleRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	runbookID := fs.String("runbook", "", "Runbook identifier (e.g. RBK-DISK-001 or disk_cleanup_var_log)")
	resourceID := fs.String("resource", "", "Target resource path or service name (e.g. /var/log)")
	targetID := fs.String("target", "", "Target resource path or service name (alias for --resource)")
	auditLog := fs.String("audit-log", "/tmp/remediation-audit.log", "Path to audit ledger log file")
	lockDir := fs.String("lock-dir", "/tmp/remediation-locks", "Directory for lock coordination")
	journalDir := fs.String("journal-dir", "/tmp/remediation-journal", "Directory for WAL journal")
	dampingFile := fs.String("damping-file", "/tmp/remediation-damping.json", "Path to damping state file")
	_ = fs.Parse(args)

	effectiveTarget := *resourceID
	if effectiveTarget == "" {
		effectiveTarget = *targetID
	}

	if *runbookID == "" || effectiveTarget == "" {
		fmt.Fprintln(os.Stderr, "Error: --runbook and --target (or --resource) flags are required for 'run'")
		fs.Usage()
		os.Exit(1)
	}

	dampFile := *dampingFile
	if envDamp := os.Getenv("REMEDIATION_DAMPING_FILE"); envDamp != "" && dampFile == "/tmp/remediation-damping.json" {
		dampFile = envDamp
	}

	cfg := engine.EngineConfig{
		LockDir:          *lockDir,
		AuditLogPath:     *auditLog,
		JournalDir:       *journalDir,
		DampingStatePath: dampFile,
		HostUUID:         "remediation-ctl-node",
	}

	eng, err := engine.NewEngine(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing remediation engine: %v\n", err)
		os.Exit(1)
	}
	defer eng.Close()

	for _, rb := range defaultCatalog() {
		_ = eng.RegisterRunbook(rb)
	}

	ctx := context.Background()
	fmt.Printf("==> Starting remediation for Runbook [%s] on Resource [%s]...\n", *runbookID, effectiveTarget)
	result, err := eng.RunDirect(ctx, *runbookID, effectiveTarget)

	fmt.Println("\n--- Execution Telemetry ---")
	if result != nil {
		fmt.Printf("Transaction ID : %s\n", result.TxID)
		fmt.Printf("Final State    : %s\n", result.FinalState)
		fmt.Printf("Duration       : %v\n", result.Duration)
		fmt.Println("FSM Lifecycle Transitions:")
		for i, t := range result.Transitions {
			fmt.Printf("  [%d] %-16s -> %-16s (%s)\n", i+1, t.From, t.To, t.Reason)
		}
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[ERROR] Remediation Failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n[SUCCESS] Remediation verified, committed, and chained to audit ledger.")
}

func handleVerifyAudit(args []string) {
	fs := flag.NewFlagSet("verify-audit", flag.ExitOnError)
	filePath := fs.String("file", "", "Path to audit ledger log file")
	_ = fs.Parse(args)

	if *filePath == "" {
		fmt.Fprintln(os.Stderr, "Error: --file flag is required for 'verify-audit'")
		fs.Usage()
		os.Exit(1)
	}

	report, err := audit.VerifyLedgerFile(*filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[INTEGRITY FAILURE] %v\n", err)
		os.Exit(1)
	}

	fmt.Println("==================================================================")
	fmt.Println("  CRYPTOGRAPHIC AUDIT LEDGER INTEGRITY VERIFIED                   ")
	fmt.Println("==================================================================")
	fmt.Printf("  Ledger Path     : %s\n", *filePath)
	fmt.Printf("  Status          : VALID (100%% Monotonic Hash Chain Continuity)\n")
	fmt.Printf("  Total Records   : %d\n", report.TotalRecords)
	fmt.Printf("  Genesis Hash H0 : %s\n", report.GenesisHash)
	fmt.Printf("  Latest Tail Hash: %s\n", report.TailHash)
	fmt.Printf("  Verification At : %s\n", report.VerifiedAt.Format(time.RFC3339))
	fmt.Println("==================================================================")
}

func handleStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	journalDir := fs.String("journal-dir", "/tmp/remediation-journal", "Directory for WAL journal")
	_ = fs.Parse(args)

	fmt.Println("==================================================================")
	fmt.Println("  AUTONOMOUS REMEDIATION ENGINE STATUS                            ")
	fmt.Println("==================================================================")

	j, err := rollback.NewJournal(*journalDir)
	if err != nil {
		fmt.Printf("Journal Status    : Error opening (%v)\n", err)
	} else {
		pending, err := j.ListPending()
		if err != nil {
			fmt.Printf("Pending Recovery  : Error reading (%v)\n", err)
		} else {
			fmt.Printf("Pending Recovery  : %d uncommitted WAL transactions\n", len(pending))
			for _, rec := range pending {
				fmt.Printf("  - TX: %s | State: %s | Runbook: %s | Target: %s\n",
					rec.TxID, rec.State, rec.RunbookID, rec.ResourceID)
			}
		}
	}

	catalog := defaultCatalog()
	fmt.Printf("Available Runbooks: %d registered\n", len(catalog))
	for _, rb := range catalog {
		fmt.Printf("  - [%s] %s (Target: %s, Severity: %s)\n",
			rb.ID, rb.Name, rb.TargetResourceID, rb.Severity)
	}

	fmt.Println("==================================================================")
}

func handleListRunbooks(args []string) {
	catalog := defaultCatalog()
	fmt.Println("==================================================================")
	fmt.Println("  AVAILABLE PRODUCTION RUNBOOKS                                   ")
	fmt.Println("==================================================================")
	fmt.Printf("Total Runbooks: %d registered\n\n", len(catalog))
	for i, rb := range catalog {
		fmt.Printf("[%d] ID: %s\n", i+1, rb.ID)
		fmt.Printf("    Name             : %s\n", rb.Name)
		fmt.Printf("    Target Resource  : %s\n", rb.TargetResourceID)
		fmt.Printf("    Severity         : %s\n", rb.Severity)
		fmt.Printf("    Max Execution    : %v\n", rb.BlastRadius.MaxExecutionTime)
		if rb.BlastRadius.MaxBytesMutated > 0 {
			fmt.Printf("    Max Bytes Mutated: %d bytes\n", rb.BlastRadius.MaxBytesMutated)
		}
		if rb.BlastRadius.MaxFilesModified > 0 {
			fmt.Printf("    Max Files Mod    : %d files\n", rb.BlastRadius.MaxFilesModified)
		}
		fmt.Printf("    Preconditions    : %d checks\n", len(rb.Preconditions))
		for _, p := range rb.Preconditions {
			fmt.Printf("      - %s (%s)\n", p.Name, p.Type)
		}
		fmt.Printf("    Actions          : %d steps\n", len(rb.Actions))
		for _, a := range rb.Actions {
			fmt.Printf("      - %s\n", a.Name)
		}
		fmt.Printf("    Postconditions   : %d checks\n", len(rb.Postconditions))
		for _, post := range rb.Postconditions {
			fmt.Printf("      - %s (%s)\n", post.Name, post.Type)
		}
		fmt.Println("------------------------------------------------------------------")
	}
}

func handleDampingStatus(args []string) {
	fs := flag.NewFlagSet("damping-status", flag.ExitOnError)
	dampingFile := fs.String("damping-file", "/tmp/remediation-damping.json", "Path to damping state file")
	resource := fs.String("resource", "", "Target resource (optional, checks specific resource)")
	_ = fs.Parse(args)

	fmt.Println("==================================================================")
	fmt.Println("  FLAPPING DAMPING & CIRCUIT BREAKER STATUS                       ")
	fmt.Println("==================================================================")
	fmt.Printf("Damping State File: %s\n", *dampingFile)

	ctrl, err := damping.NewController(*dampingFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading damping controller: %v\n", err)
		os.Exit(1)
	}

	if *resource != "" {
		canExec, reason := ctrl.CanExecute(*resource)
		st := ctrl.GetStatus(*resource)
		fmt.Printf("\nResource: %s\n", *resource)
		fmt.Printf("  Executable Now : %v\n", canExec)
		if !canExec {
			fmt.Printf("  Block Reason   : %s\n", reason)
		}
		if st != nil {
			fmt.Printf("  Tripped        : %v\n", st.Tripped)
			if st.Tripped {
				fmt.Printf("  Quarantine Thru: %s\n", st.QuarantineUntil.UTC().Format(time.RFC3339))
				fmt.Printf("  Trip Reason    : %s\n", st.TripReason)
			}
			fmt.Printf("  Executions (%d) :\n", len(st.Executions))
			for _, t := range st.Executions {
				fmt.Printf("    - %s (%v ago)\n", t.UTC().Format(time.RFC3339), time.Since(t).Round(time.Second))
			}
		} else {
			fmt.Println("  No execution history recorded for this resource.")
		}
	} else {
		statuses := ctrl.GetAllStatuses()
		if len(statuses) == 0 {
			fmt.Println("\nNo resource flapping records tracked (all circuits nominal).")
		} else {
			fmt.Printf("\nTracked Resources: %d\n", len(statuses))
			for resName, st := range statuses {
				canExec, reason := ctrl.CanExecute(resName)
				fmt.Printf("\n* Resource: %s\n", resName)
				fmt.Printf("  Executable Now : %v\n", canExec)
				if !canExec {
					fmt.Printf("  Block Reason   : %s\n", reason)
				}
				fmt.Printf("  Tripped        : %v\n", st.Tripped)
				if st.Tripped {
					fmt.Printf("  Quarantine Thru: %s\n", st.QuarantineUntil.UTC().Format(time.RFC3339))
					fmt.Printf("  Trip Reason    : %s\n", st.TripReason)
				}
				fmt.Printf("  Executions (%d) :\n", len(st.Executions))
				for _, t := range st.Executions {
					fmt.Printf("    - %s (%v ago)\n", t.UTC().Format(time.RFC3339), time.Since(t).Round(time.Second))
				}
			}
		}
	}
	fmt.Println("==================================================================")
}

func handleTriage(args []string) {
	fs := flag.NewFlagSet("triage", flag.ExitOnError)
	incidentFlag := fs.String("incident", "", "Incident log text or file path")
	apiKeyFlag := fs.String("api-key", "", "API key (defaults to $NVIDIA_API_KEY or $OPENAI_API_KEY)")
	baseURLFlag := fs.String("base-url", "", "Base URL (defaults to https://integrate.api.nvidia.com/v1 if NVIDIA key is used, or https://api.openai.com/v1)")
	modelFlag := fs.String("model", "", "Model name (defaults to nvidia/nemotron-3-ultra-550b-a55b or gpt-4o)")
	executeFlag := fs.Bool("execute", false, "Execute proposed remediation through deterministic engine (default: false dry-run)")

	auditLog := fs.String("audit-log", "/tmp/remediation-audit.log", "Path to audit ledger log file")
	lockDir := fs.String("lock-dir", "/tmp/remediation-locks", "Directory for lock coordination")
	journalDir := fs.String("journal-dir", "/tmp/remediation-journal", "Directory for WAL journal")
	dampingFile := fs.String("damping-file", "/tmp/remediation-damping.json", "Path to damping state file")

	_ = fs.Parse(args)

	// 1. Resolve Incident Log
	incidentInput := strings.TrimSpace(*incidentFlag)
	var incidentLog string
	if incidentInput != "" {
		if fi, err := os.Stat(incidentInput); err == nil && !fi.IsDir() {
			data, err := os.ReadFile(incidentInput)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading incident file %s: %v\n", incidentInput, err)
				os.Exit(1)
			}
			incidentLog = strings.TrimSpace(string(data))
		} else {
			incidentLog = incidentInput
		}
	} else {
		// Read from stdin if available
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			stdinBytes, err := io.ReadAll(os.Stdin)
			if err == nil {
				incidentLog = strings.TrimSpace(string(stdinBytes))
			}
		}
	}

	if incidentLog == "" {
		fmt.Fprintln(os.Stderr, "Error: --incident flag or piped stdin containing incident log is required")
		fs.Usage()
		os.Exit(1)
	}

	// 2. Resolve API Key
	apiKey := strings.TrimSpace(*apiKeyFlag)
	if apiKey == "" {
		apiKey = strings.TrimSpace(os.Getenv("NVIDIA_API_KEY"))
		if apiKey == "" {
			apiKey = strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
		}
	}
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "Error: API key required. Provide via --api-key flag or set $NVIDIA_API_KEY / $OPENAI_API_KEY")
		os.Exit(1)
	}

	// 3. Resolve Base URL
	baseURL := strings.TrimSpace(*baseURLFlag)
	if baseURL == "" {
		if strings.HasPrefix(apiKey, "nvapi-") || os.Getenv("NVIDIA_API_KEY") != "" {
			baseURL = "https://integrate.api.nvidia.com/v1"
		} else {
			baseURL = "https://api.openai.com/v1"
		}
	}

	// 4. Resolve Model
	modelName := strings.TrimSpace(*modelFlag)
	if modelName == "" {
		if strings.Contains(baseURL, "nvidia") || strings.HasPrefix(apiKey, "nvapi-") {
			modelName = "nvidia/nemotron-3-ultra-550b-a55b"
		} else {
			modelName = "gpt-4o"
		}
	}

	ctx := context.Background()

	fmt.Println("==================================================================")
	fmt.Println("  AI INCIDENT TRIAGE PROPOSER                                     ")
	fmt.Println("==================================================================")
	fmt.Printf("Model           : %s\n", modelName)
	fmt.Printf("Base URL        : %s\n", baseURL)
	fmt.Println("Mode            :", func() string {
		if *executeFlag {
			return "LIVE EXECUTION (AI Proposal -> Deterministic Enforcement)"
		}
		return "DRY-RUN (AI Proposal -> Inspection Only)"
	}())
	fmt.Println("------------------------------------------------------------------")
	fmt.Println("Consulting AI model for incident triage and runbook selection...")

	aiCfg := ai.Config{
		BaseURL: baseURL,
		APIKey:  apiKey,
		Model:   modelName,
		Timeout: 60 * time.Second,
	}

	proposal, err := ai.ProposeRemediation(ctx, aiCfg, incidentLog)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[ERROR] AI Triage failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n==================================================================")
	fmt.Println("  AI PROPOSAL & REASONING TRACE                                   ")
	fmt.Println("==================================================================")
	if proposal.ReasoningContent != "" {
		fmt.Println("[Reasoning Trace]:")
		fmt.Println(proposal.ReasoningContent)
		fmt.Println("------------------------------------------------------------------")
	}
	fmt.Printf("Diagnosis       : %s\n", proposal.Diagnosis)
	fmt.Printf("Proposed Runbook: %s\n", proposal.RunbookID)
	fmt.Printf("Target Resource : %s\n", proposal.TargetResource)
	fmt.Printf("Severity        : %s\n", proposal.Severity)
	fmt.Println("==================================================================")

	// Fetch runbook from catalog to inspect preconditions and blast radius
	cat := runbooks.NewDefaultCatalog()
	matchedRunbook, err := cat.Get(proposal.RunbookID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[REJECTED] Proposed runbook %s is not in deterministic catalog: %v\n", proposal.RunbookID, err)
		os.Exit(1)
	}

	if !*executeFlag {
		fmt.Println("\n[DETERMINISTIC PRECHECKS (DRY-RUN)]")
		fmt.Printf("Runbook Name     : %s\n", matchedRunbook.Name)
		fmt.Printf("Runbook ID       : %s\n", matchedRunbook.ID)
		fmt.Printf("Target Resource  : %s\n", proposal.TargetResource)
		fmt.Printf("Max Execution    : %v\n", matchedRunbook.BlastRadius.MaxExecutionTime)
		if matchedRunbook.BlastRadius.MaxBytesMutated > 0 {
			fmt.Printf("Max Bytes Mutated: %d bytes\n", matchedRunbook.BlastRadius.MaxBytesMutated)
		}
		if matchedRunbook.BlastRadius.MaxFilesModified > 0 {
			fmt.Printf("Max Files Mod    : %d files\n", matchedRunbook.BlastRadius.MaxFilesModified)
		}
		if len(matchedRunbook.BlastRadius.AllowedPathPrefixes) > 0 {
			fmt.Printf("Allowed Prefixes : %v\n", matchedRunbook.BlastRadius.AllowedPathPrefixes)
		}

		fmt.Printf("\nPrecondition Gates (%d):\n", len(matchedRunbook.Preconditions))
		for i, pre := range matchedRunbook.Preconditions {
			fmt.Printf("  [%d] %s (%s)\n", i+1, pre.Name, pre.Type)
		}

		fmt.Printf("\nActions to be Executed (%d):\n", len(matchedRunbook.Actions))
		for i, act := range matchedRunbook.Actions {
			fmt.Printf("  [%d] %s\n", i+1, act.Name)
		}

		fmt.Printf("\nPostcondition Assertions (%d):\n", len(matchedRunbook.Postconditions))
		for i, post := range matchedRunbook.Postconditions {
			fmt.Printf("  [%d] %s (%s)\n", i+1, post.Name, post.Type)
		}

		fmt.Println("\n------------------------------------------------------------------")
		fmt.Println("[DRY-RUN COMPLETE] Remediation was NOT executed.")
		fmt.Println("Architectural Principle: 'AI proposes. Deterministic systems enforce.'")
		fmt.Println("To execute through the deterministic engine, run with --execute.")
		fmt.Println("==================================================================")
		return
	}

	// LIVE EXECUTION: AI proposes. Deterministic systems enforce.
	fmt.Println("\n[LIVE EXECUTION] Enforcing remediation through deterministic engine...")

	dampFile := *dampingFile
	if envDamp := os.Getenv("REMEDIATION_DAMPING_FILE"); envDamp != "" && dampFile == "/tmp/remediation-damping.json" {
		dampFile = envDamp
	}

	cfg := engine.EngineConfig{
		LockDir:          *lockDir,
		AuditLogPath:     *auditLog,
		JournalDir:       *journalDir,
		DampingStatePath: dampFile,
		HostUUID:         "remediation-ctl-node",
	}

	eng, err := engine.NewEngine(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing remediation engine: %v\n", err)
		os.Exit(1)
	}
	defer eng.Close()

	for _, rb := range defaultCatalog() {
		_ = eng.RegisterRunbook(rb)
	}

	alert := &model.Alert{
		ID:          fmt.Sprintf("ai-triage-%d", time.Now().UnixNano()),
		Fingerprint: fmt.Sprintf("fp-%s-%s", proposal.RunbookID, proposal.TargetResource),
		Source:      "ai-triage",
		ResourceID:  proposal.TargetResource,
		Severity:    model.Severity(proposal.Severity),
		Labels: map[string]string{
			"runbook_id":   proposal.RunbookID,
			"ai_diagnosis": proposal.Diagnosis,
			"ai_model":     modelName,
		},
		ReceivedAt: time.Now().UTC(),
	}

	fmt.Printf("==> Starting deterministic remediation for Runbook [%s] on Resource [%s]...\n",
		proposal.RunbookID, proposal.TargetResource)

	result, err := eng.Remediate(ctx, alert)

	fmt.Println("\n--- Execution Telemetry ---")
	if result != nil {
		fmt.Printf("Transaction ID : %s\n", result.TxID)
		fmt.Printf("Final State    : %s\n", result.FinalState)
		fmt.Printf("Duration       : %v\n", result.Duration)
		fmt.Println("FSM Lifecycle Transitions:")
		for i, t := range result.Transitions {
			fmt.Printf("  [%d] %-16s -> %-16s (%s)\n", i+1, t.From, t.To, t.Reason)
		}
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[ERROR] Deterministic Enforcement Failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n[SUCCESS] AI proposal verified and enforced by deterministic engine.")
	fmt.Println("Remediation verified, committed, and chained to cryptographic audit ledger.")
}

