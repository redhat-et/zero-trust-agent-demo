// Package main provides a CLI for learning RFC 8693 token exchange.
//
// YOUR TASK: Complete Task 6 to build a working CLI that:
// 1. Loads configuration from environment
// 2. Obtains or accepts a subject token
// 3. Exchanges it for a token with a different audience
// 4. Displays the before/after comparison
// 5. Verifies the exchange was successful
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	// TODO: Task 6 - Implement CLI argument parsing
	//
	// Suggested subcommands:
	//
	// exchange: Exchange a provided token
	//   --subject-token: The JWT to exchange
	//   --audience: Target audience for the new token
	//
	// demo: Get a fresh token and exchange it
	//   --target-audience: Target audience for the new token
	//
	// Environment variables (used by both):
	//   TOKEN_URL, CLIENT_ID, CLIENT_SECRET

	// Simple flag-based approach (no subcommands)
	subjectToken := flag.String("subject-token", "", "JWT to exchange (or set via stdin)")
	audience := flag.String("audience", "", "Target audience for the new token")
	demo := flag.Bool("demo", false, "Demo mode: get a fresh token and exchange it")
	flag.Parse()

	_ = subjectToken // Remove when you use
	_ = audience     // Remove when you use
	_ = demo         // Remove when you use

	// TODO: Load configuration
	// cfg, err := LoadConfig()
	// if err != nil { ... }

	// TODO: Get subject token
	// If --demo flag is set:
	//   token, err := cfg.GetInitialToken()
	// Else:
	//   token := *subjectToken (or read from stdin)

	// TODO: Validate audience is provided
	if *audience == "" {
		fmt.Fprintln(os.Stderr, "Error: --audience is required")
		os.Exit(1)
	}

	// TODO: Perform token exchange
	// req := &ExchangeRequest{
	//     SubjectToken:   token,
	//     TargetAudience: *audience,
	// }
	// newToken, err := ExchangeToken(cfg, req)

	// TODO: Display comparison
	// PrintTokenComparison(token, newToken)

	// TODO: Verify the exchange
	// err = VerifyExchange(token, newToken, *audience)
	// if err != nil { ... }

	fmt.Println("STS Token Exchange - Task 6: Implement this CLI")
	fmt.Println("See README.md for instructions")
}
