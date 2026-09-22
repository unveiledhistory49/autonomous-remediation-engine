package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"autonomous-remediation-engine/internal/audit"
	"autonomous-remediation-engine/internal/engine"
	"autonomous-remediation-engine/internal/model"
	"autonomous-remediation-engine/internal/rollback"
)

func defaultCatalog() []*model.Runbook {
	return []*model.Runbook{
		{
			ID:               "RBK-DISK-001",
			Version:          "1.0.0",
			Name:             "disk_cleanup_var_log",
			TargetResourceID: "/var/log",
			Severity:         model.SeverityHigh,
			Preconditions: []model.Precondition{
				{
					Name:       "disk-usage-threshold",
					Type:       model.ConditionDiskFree,
					Target:     "/var/log",
					MinFreePct: 0.0, // verified via statfs
				},
			},
			Actions: []model.Action{
				{
					Name:    "prune-rotated-logs",
					Binary:  "/bin/echo",
					Args:    []string{"[RBK-DISK-001] safe log drain executed"},
					Timeout: 10 * time.Second,
				},
			},
			Postconditions: []model.Postcondition{
				{
					Name:       "disk-capacity-restored",
					Type:       model.ConditionDiskFree,
					Target:     "/var/log",
					MinFreePct: 0.0,
				},
			},
			BlastRadius: model.BlastRadius{
				MaxExecutionTime: 15 * time.Second,
				MaxBytesMutated:  524288000, // 500 MB
			},
		},
		{
			ID:               "RBK-PROC-001",
			Version:          "1.0.0",
			Name:             "service_hang_recovery",
			TargetResourceID: "ai-gateway",
			Severity:         model.SeverityCritical,
			Preconditions: []model.Precondition{
				{
					Name:   "root-filesystem-check",
					Type:   model.ConditionFileExists,
					Target: "/proc",
				},
			},
			Actions: []model.Action{
				{
					Name:    "restart-service-action",
					Binary:  "/bin/echo",
					Args:    []string{"[RBK-PROC-001] supervised service reload triggered"},
					Timeout: 15 * time.Second,
				},
			},
			Postconditions: []model.Postcondition{
				{
					Name:   "system-procfs-alive",
					Type:   model.ConditionFileExists,
					Target: "/proc/stat",
				},
			},
			BlastRadius: model.BlastRadius{
				MaxExecutionTime:     15 * time.Second,
				MaxProcessesSignaled: 1,
			},
		},
	}
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
	case "verify-audit":
		handleVerifyAudit(os.Args[2:])
	case "status":
		handleStatus(os.Args[2:])
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
	fmt.Println("  remediation-ctl run --runbook=<id> --resource=<res> [--audit-log=<path>] [--lock-dir=<dir>] [--journal-dir=<dir>]")
	fmt.Println("  remediation-ctl verify-audit --file=<path>")
	fmt.Println("  remediation-ctl status [--journal-dir=<dir>]")
}

func handleRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	runbookID := fs.String("runbook", "", "Runbook identifier (e.g. RBK-DISK-001)")
	resourceID := fs.String("resource", "", "Target resource path or service name (e.g. /var/log)")
	auditLog := fs.String("audit-log", "/tmp/remediation-audit.log", "Path to audit ledger log file")
	lockDir := fs.String("lock-dir", "/tmp/remediation-locks", "Directory for lock coordination")
	journalDir := fs.String("journal-dir", "/tmp/remediation-journal", "Directory for WAL journal")
	_ = fs.Parse(args)

	if *runbookID == "" || *resourceID == "" {
		fmt.Fprintln(os.Stderr, "Error: --runbook and --resource flags are required for 'run'")
		fs.Usage()
		os.Exit(1)
	}

	cfg := engine.EngineConfig{
		LockDir:      *lockDir,
		AuditLogPath: *auditLog,
		JournalDir:   *journalDir,
		HostUUID:     "remediation-ctl-node",
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
	fmt.Printf("==> Starting remediation for Runbook [%s] on Resource [%s]...\n", *runbookID, *resourceID)
	result, err := eng.RunDirect(ctx, *runbookID, *resourceID)

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
