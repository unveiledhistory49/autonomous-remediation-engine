package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

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
