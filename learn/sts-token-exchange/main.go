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

	exchangeCmd := flag.NewFlagSet("exchange", flag.ExitOnError)
	exchangeSubjectToken := exchangeCmd.String("subject-token", "", "JWT to exchange (or set via stdin)")
	exchangeAudience := exchangeCmd.String("audience", "", "Target audience for the new token")

	demoCmd := flag.NewFlagSet("demo", flag.ExitOnError)
	demoTargetAudience := demoCmd.String("target-audience", "", "Target audience for the new token")

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Error: missing subcommand")
		os.Exit(1)
	}

	cfg, err := LoadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: failed to load configuration:", err)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "exchange":
		err := exchangeCmd.Parse(os.Args[2:])
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error: failed to parse exchange command:", err)
			os.Exit(1)
		}
		if *exchangeSubjectToken == "" {
			fmt.Fprintln(os.Stderr, "Error: --subject-token is required")
			os.Exit(1)
		}
		if *exchangeAudience == "" {
			fmt.Fprintln(os.Stderr, "Error: --audience is required")
			os.Exit(1)
		}
	case "demo":
		err := demoCmd.Parse(os.Args[2:])
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error: failed to parse demo command:", err)
			os.Exit(1)
		}
		if *demoTargetAudience == "" {
			fmt.Fprintln(os.Stderr, "Error: --target-audience is required")
			os.Exit(1)
		}
		token, err := cfg.GetInitialToken()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error: failed to get initial token:", err)
			os.Exit(1)
		}
		*exchangeSubjectToken = token
		*exchangeAudience = *demoTargetAudience
	default:
		fmt.Fprintln(os.Stderr, "Error: invalid subcommand")
		os.Exit(1)
	}

	// Create scope from target audience
	scope := *exchangeAudience + "-aud"
	req := &ExchangeRequest{
		SubjectToken:   *exchangeSubjectToken,
		TargetAudience: *exchangeAudience,
		Scopes:         []string{scope},
	}
	newToken, err := ExchangeToken(cfg, req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: failed to exchange token:", err)
		os.Exit(1)
	}
	err = VerifyExchange(*exchangeSubjectToken, newToken, *exchangeAudience)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: failed to verify exchange:", err)
		os.Exit(1)
	}
	fmt.Println("Exchange successful")
	PrintTokenComparison(*exchangeSubjectToken, newToken)
	active, err := IntrospectToken(cfg, newToken)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: failed to introspect token:", err)
		os.Exit(1)
	}
	fmt.Println("Token is active:", active)
}
