package main

import (
	"context"
	"fmt"
	"os"

	"grafttangled/internal/tangled"
)

func main() {
	c := tangled.New(tangled.Config{
		PDSBaseURL: "https://pds.cyberwild.org",
		Handle:     "graft.pds.cyberwild.org",
	})
	ctx := context.Background()
	if err := c.Login(ctx, os.Args[1]); err != nil {
		fmt.Println("login error:", err)
		os.Exit(1)
	}
	fmt.Println("logged in, did:", c.DID())

	res, err := c.CreateRepo(ctx, tangled.CreateRepoInput{
		Knot:          "knot.cyberwild.org",
		Rkey:          "smoketest1",
		Name:          "smoketest1",
		DefaultBranch: "main",
		Source:        "https://f1.cyberwild.org/forgeadmin/graft-test-v2.git",
		Description:   "graft-tangled bridge smoke test",
	})
	if err != nil {
		fmt.Println("createrepo error:", err)
		os.Exit(1)
	}
	fmt.Printf("repo created: repoDid=%s atURI=%s\n", res.RepoDid, res.AtURI)

	issueURI, err := c.CreateIssue(ctx, res.RepoDid, "smoke test issue", "created by graft-tangled smoketest")
	if err != nil {
		fmt.Println("createissue error:", err)
		os.Exit(1)
	}
	fmt.Println("issue created:", issueURI)
}
