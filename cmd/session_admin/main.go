package main

// session_admin is a small operator tool over the M8 session store: it imports a
// legacy session file into the project database, lists what is stored, or deletes
// an account, without the server running.
//
// It NEVER prints a credential: account labels, cookie names, counts and paths
// only. That is why it is safe to run in a terminal that is being recorded.
//
// Usage:
//
//	session_admin -db onvif_logs.db -list
//	session_admin -db onvif_logs.db -import /path/to/user_us-west_x.json
//	session_admin -db onvif_logs.db -delete us-west:user@example.test
//	session_admin -db onvif_logs.db -modes
//
// The import is the SAME non-destructive, idempotent call the server makes at
// start-up (tuyaqr.ImportSessionFile): the source file is read only, and an
// account already in the database is skipped rather than overwritten.

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"dengan.dev/camera-streamer/internal/tuyaqr"
)

func main() {
	db := flag.String("db", "onvif_logs.db", "path to the project database")
	list := flag.Bool("list", false, "list the stored accounts (names and counts only)")
	importPath := flag.String("import", "", "import a legacy session JSON file (non-destructive, idempotent)")
	deleteAccount := flag.String("delete", "", "delete an account, given as region:email")
	modes := flag.Bool("modes", false, "print the observed permissions of the database and its -wal/-shm")
	flag.Parse()

	store, err := tuyaqr.NewSQLiteSessionStore(*db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open %s: %v\n", *db, err)
		os.Exit(1)
	}
	defer store.Close()

	fmt.Printf("store: kind=%s location=%s\n", store.Kind(), store.Location())

	if *modes {
		fmt.Println("permissions:")
		for _, m := range store.ObservedModes() {
			verdict := "owner-only"
			if m.Mode != "0600" {
				verdict = "GROUP/WORLD ACCESSIBLE"
			}
			fmt.Printf("  %s %s (%s)\n", m.Mode, m.Path, verdict)
		}
	}

	if *importPath != "" {
		res, err := tuyaqr.ImportSessionFile(store, *importPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "import: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("import: imported=%t alreadyStored=%t account=%s/%s cookies=%d names=%v dest=%s\n",
			res.Imported, res.AlreadyStored, res.Region, res.Email, res.CookieCount, res.CookieNames, res.DestKind)
		fmt.Printf("        %s\n", res.Detail)
	}

	if *deleteAccount != "" {
		region, email, ok := splitAccount(*deleteAccount)
		if !ok {
			fmt.Fprintf(os.Stderr, "delete needs region:email, got %q\n", *deleteAccount)
			os.Exit(2)
		}
		if err := store.Delete(tuyaqr.Account{Region: region, Email: email}); err != nil {
			fmt.Fprintf(os.Stderr, "delete: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("delete: %s/%s removed\n", region, email)
	}

	stored, err := store.Accounts()
	if err != nil {
		fmt.Fprintf(os.Stderr, "list: %v\n", err)
		os.Exit(1)
	}
	if *list || len(stored) > 0 {
		fmt.Printf("stored accounts: %d\n", len(stored))
		for _, s := range stored {
			fmt.Printf("  %s cookies=%d hasAuthPair=%t lastRefresh=%s updatedAt=%s\n",
				s.Account, s.CookieCount, s.HasAuthPair,
				orNone(s.LastRefresh), s.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"))
		}
	}
}

func splitAccount(v string) (string, string, bool) {
	idx := strings.Index(v, ":")
	if idx <= 0 || idx == len(v)-1 {
		return "", "", false
	}
	return strings.TrimSpace(v[:idx]), strings.TrimSpace(v[idx+1:]), true
}

func orNone(t interface{ IsZero() bool }) string {
	if t == nil || t.IsZero() {
		return "never"
	}
	return fmt.Sprintf("%v", t)
}
