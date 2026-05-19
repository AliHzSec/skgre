package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

const version = "1.1.0"

const (
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiReset  = "\x1b[0m"
)

const banner = `
   _____    __ __   ______    ____     ______
  / ___/   / //_/  / ____/   / __ \   / ____/
  \__ \   / ,<    / / __    / /_/ /  / __/   
 ___/ /  / /| |  / /_/ /   / _, _/  / /___   
/____/  /_/ |_|  \____/   /_/ |_|  /_____/   

  v` + version + ` - github.com/AliHzSec
`

var repoNameRegex = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

type Options struct {
	Mode          string
	IdentityFile  string
	Username      string
	Word          string
	Wordlist      string
	Threads       int
	ExistingOnly  bool
	EnableFuzz    bool
	FuzzBefore    bool
	FuzzAfter     bool
	FuzzWords     string
	FuzzFile      string
	Silent        bool
	OutputEnabled bool
	OutputPath    string
	Debug         bool
	NoColor       bool
	PrivateOnly   bool
}

type Stats struct {
	total     int64
	checked   int64
	found     int64
	errors    int64
	startTime time.Time
}

func (s *Stats) increment() {
	atomic.AddInt64(&s.checked, 1)
}

func (s *Stats) addFound() {
	atomic.AddInt64(&s.found, 1)
}

func (s *Stats) addError() {
	atomic.AddInt64(&s.errors, 1)
}

func printBanner() {
	fmt.Printf(banner)
}

func printConfig(opts *Options, username string, totalWords int) {
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf(":: Mode             : %s\n", opts.Mode)
	fmt.Printf(":: Identity File    : %s\n", opts.IdentityFile)
	if opts.Mode == "probe" {
		fmt.Printf(":: Target User      : %s\n", username)
	} else {
		fmt.Printf(":: GitHub User      : %s\n", username)
	}
	if opts.Word != "" {
		fmt.Printf(":: Word             : %s\n", opts.Word)
	}
	if opts.Wordlist != "" {
		fmt.Printf(":: Wordlist         : %s\n", opts.Wordlist)
	}
	fmt.Printf(":: Total Words      : %d\n", totalWords)
	fmt.Printf(":: Threads          : %d\n", opts.Threads)
	fmt.Printf(":: Fuzz Mode        : %v\n", opts.EnableFuzz)
	if opts.EnableFuzz {
		position := "after"
		if opts.FuzzBefore {
			position = "before"
		}
		fmt.Printf(":: Fuzz Position    : %s\n", position)
		if opts.FuzzWords != "" {
			fmt.Printf(":: Fuzz Words       : %s\n", opts.FuzzWords)
		}
		if opts.FuzzFile != "" {
			fmt.Printf(":: Fuzz File        : %s\n", opts.FuzzFile)
		}
	}
	if opts.OutputEnabled {
		dir := opts.OutputPath
		if dir == "" {
			dir = "."
		}
		fmt.Printf(":: Output           : %s\n", dir)
	}
	fmt.Printf(":: Existing Only    : %v\n", opts.ExistingOnly)
	fmt.Printf(":: Private Only     : %v\n", opts.PrivateOnly)
	fmt.Println(strings.Repeat("-", 50))
	fmt.Println()
}

func checkSSHKey(keyPath string) (string, error) {
	cmd := exec.Command("ssh",
		"-i", keyPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "BatchMode=yes",
		"-T", "git@github.com",
	)

	output, _ := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(output))

	if strings.Contains(outputStr, "Permission denied") {
		return "", fmt.Errorf("SSH key is not registered on any GitHub account")
	}

	// Extract username from "Hi USERNAME! You've successfully authenticated..."
	if strings.Contains(outputStr, "Hi ") && strings.Contains(outputStr, "!") {
		start := strings.Index(outputStr, "Hi ") + 3
		end := strings.Index(outputStr[start:], "!")
		if end > 0 {
			return outputStr[start : start+end], nil
		}
	}

	return "", fmt.Errorf("unexpected SSH response: %s", outputStr)
}

func getOrganizations(username string) ([]string, error) {
	url := fmt.Sprintf("https://api.github.com/users/%s/orgs", username)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var orgs []struct {
		Login string `json:"login"`
	}
	if err := json.Unmarshal(body, &orgs); err != nil {
		return nil, err
	}

	var names []string
	for _, org := range orgs {
		names = append(names, org.Login)
	}
	return names, nil
}

func checkKeyPermissions(keyPath string) error {
	info, err := os.Stat(keyPath)
	if err != nil {
		return fmt.Errorf("cannot access key file: %v", err)
	}

	mode := info.Mode().Perm()
	if mode != 0600 {
		return fmt.Errorf("incorrect permissions on SSH key file '%s' (got %o, need 600)\n  Fix with: chmod 600 %s", keyPath, mode, keyPath)
	}
	return nil
}

func sanitizeAndSortWordlist(inputPath string) (string, int, error) {
	inFile, err := os.Open(inputPath)
	if err != nil {
		return "", 0, fmt.Errorf("cannot open wordlist: %v", err)
	}
	defer inFile.Close()

	seen := make(map[string]bool)
	var words []string

	scanner := bufio.NewScanner(inFile)
	// 10MB buffer for very long lines
	buf := make([]byte, 10*1024*1024)
	scanner.Buffer(buf, len(buf))

	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" {
			continue
		}
		if !repoNameRegex.MatchString(word) {
			continue
		}
		normalized := strings.ToLower(word)
		if seen[normalized] {
			continue
		}
		seen[normalized] = true
		words = append(words, normalized)
	}
	if err := scanner.Err(); err != nil {
		return "", 0, err
	}

	sort.Strings(words)

	tmpFile, err := os.CreateTemp("/tmp", "skgre-wl-*.txt")
	if err != nil {
		return "", 0, err
	}
	defer tmpFile.Close()

	w := bufio.NewWriterSize(tmpFile, 4*1024*1024)
	for _, word := range words {
		fmt.Fprintln(w, word)
	}
	if err := w.Flush(); err != nil {
		return "", 0, err
	}

	return tmpFile.Name(), len(words), nil
}

func loadFuzzWords(opts *Options) ([]string, error) {
	var fuzzWords []string

	if opts.FuzzWords != "" {
		parts := strings.Split(opts.FuzzWords, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				fuzzWords = append(fuzzWords, p)
			}
		}
	}

	if opts.FuzzFile != "" {
		f, err := os.Open(opts.FuzzFile)
		if err != nil {
			return nil, fmt.Errorf("cannot open fuzz file: %v", err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				fuzzWords = append(fuzzWords, line)
			}
		}
	}

	return fuzzWords, nil
}

func buildCandidates(word string, fuzzWords []string, opts *Options) []string {
	var candidates []string
	// Always try the base word
	candidates = append(candidates, word)

	if opts.EnableFuzz && len(fuzzWords) > 0 {
		for _, fw := range fuzzWords {
			var candidate string
			if opts.FuzzBefore {
				candidate = fw + word
			} else {
				candidate = word + fw
			}
			// validate the combined name
			if repoNameRegex.MatchString(candidate) {
				candidates = append(candidates, candidate)
			}
		}
	}

	return candidates
}

func checkRepo(username, repoName, keyPath string, debug bool) (bool, error) {
	sshURL := fmt.Sprintf("git@github.com:%s/%s.git", username, repoName)
	cmd := exec.Command("git", "ls-remote",
		"--env", fmt.Sprintf("GIT_SSH_COMMAND=ssh -i %s -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o BatchMode=yes", keyPath),
		sshURL,
	)

	// Use GIT_SSH_COMMAND env var instead
	cmd = exec.Command("git", "ls-remote", sshURL)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("GIT_SSH_COMMAND=ssh -i %s -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o BatchMode=yes", keyPath),
	)

	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	if debug {
		lines := strings.Split(strings.TrimSpace(outputStr), "\n")
		maxLines := 5
		if len(lines) < maxLines {
			maxLines = len(lines)
		}
		fmt.Printf("[DEBUG] git ls-remote %s\n", sshURL)
		for i := 0; i < maxLines; i++ {
			fmt.Printf("[DEBUG]   %s\n", lines[i])
		}
	}

	if err != nil {
		return false, nil
	}

	// If we got output (refs), repo exists and we have access
	return strings.TrimSpace(outputStr) != "", nil
}

func isPrivateRepo(username, repoName string) bool {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s", username, repoName)
	resp, err := http.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusNotFound
}

func runInfoMode(opts *Options) error {
	gologger.Info().Msgf("Checking SSH key: %s", opts.IdentityFile)

	if err := checkKeyPermissions(opts.IdentityFile); err != nil {
		return err
	}

	username, err := checkSSHKey(opts.IdentityFile)
	if err != nil {
		return err
	}

	if opts.Silent {
		fmt.Printf("%s - https://github.com/%s\n", username, username)
	} else {
		gologger.Info().Msgf("Authenticated as: %s - https://github.com/%s", username, username)
	}

	orgs, err := getOrganizations(username)
	if err != nil {
		gologger.Warning().Msgf("Could not fetch organizations: %v", err)
	} else {
		for _, org := range orgs {
			if opts.Silent {
				fmt.Printf("%s - https://github.com/%s\n", org, org)
			} else {
				gologger.Info().Msgf("Member of organization: %s - https://github.com/%s", org, org)
			}
		}
	}

	return nil
}

func runEnumMode(opts *Options) error {
	if err := checkKeyPermissions(opts.IdentityFile); err != nil {
		return err
	}

	// Step 1: Auth check
	gologger.Info().Msgf("Checking SSH key: %s", opts.IdentityFile)
	username, err := checkSSHKey(opts.IdentityFile)
	if err != nil {
		return err
	}

	gologger.Info().Msgf("Authenticated as: %s - https://github.com/%s", username, username)

	orgs, err := getOrganizations(username)
	if err != nil {
		gologger.Warning().Msgf("Could not fetch organizations: %v", err)
	} else {
		for _, org := range orgs {
			gologger.Info().Msgf("Member of organization: %s - https://github.com/%s", org, org)
		}
	}

	// Step 2: Build word list
	var baseWords []string
	var tmpFile string
	var totalBase int

	if opts.Word != "" {
		word := strings.TrimSpace(opts.Word)
		if !repoNameRegex.MatchString(word) {
			return fmt.Errorf("invalid repository name: %s", word)
		}
		baseWords = []string{word}
		totalBase = 1
	} else {
		gologger.Info().Msgf("Sanitizing and sorting wordlist...")
		var count int
		tmpFile, count, err = sanitizeAndSortWordlist(opts.Wordlist)
		if err != nil {
			return err
		}
		totalBase = count
		gologger.Info().Msgf("Wordlist ready: %d valid entries", totalBase)

		// Setup cleanup
		cleanup := func() {
			if tmpFile != "" {
				os.Remove(tmpFile)
			}
		}
		defer cleanup()

		// Handle Ctrl+C
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sigChan
			fmt.Print("\r\x1b[2K")
			gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
			gologger.Warning().Msg("Caught keyboard interrupt (Ctrl-C)")
			gologger.Info().Msg("Cleaning up temporary files...")
			cleanup()
			os.Exit(1)
		}()
	}

	// Step 3: Load fuzz words
	var fuzzWords []string
	if opts.EnableFuzz {
		fuzzWords, err = loadFuzzWords(opts)
		if err != nil {
			return err
		}
		gologger.Info().Msgf("Fuzz words loaded: %d entries", len(fuzzWords))
	}

	// Step 4: Calculate total candidates
	multiplier := 1
	if opts.EnableFuzz && len(fuzzWords) > 0 {
		multiplier = 1 + len(fuzzWords) // base word + fuzzed variants
	}

	totalCandidates := int64(totalBase * multiplier)

	// Step 5: Setup output
	var outputFile *os.File
	if opts.OutputEnabled {
		outDir := opts.OutputPath
		if outDir == "" {
			outDir, err = os.Getwd()
			if err != nil {
				return fmt.Errorf("cannot determine current directory: %v", err)
			}
		}
		ts := time.Now().Format("20060102_150405")
		outName := fmt.Sprintf("repo_found_%s_%s.txt", username, ts)
		outPath := filepath.Join(outDir, outName)
		outputFile, err = os.Create(outPath)
		if err != nil {
			return fmt.Errorf("cannot create output file: %v", err)
		}
		defer outputFile.Close()
		gologger.Info().Msgf("Output file: %s", outPath)
	}

	// Step 6: Print config
	if !opts.Silent {
		printConfig(opts, username, int(totalCandidates))
	}

	// Step 7: Setup stats
	stats := &Stats{
		total:     totalCandidates,
		startTime: time.Now(),
	}

	// Step 8: Progress printer
	var printMu sync.Mutex

	drawProgress := func() {
		checked := atomic.LoadInt64(&stats.checked)
		found := atomic.LoadInt64(&stats.found)
		elapsed := time.Since(stats.startTime)
		fmt.Printf("\r\x1b[2K:: Progress: [%d/%d] :: Found: %d :: Duration: [%s] :: Errors: %d ::",
			checked, totalCandidates, found,
			formatDuration(elapsed),
			atomic.LoadInt64(&stats.errors),
		)
	}

	stopProgress := make(chan struct{})
	var progressWg sync.WaitGroup
	if !opts.Silent {
		progressWg.Add(1)
		go func() {
			defer progressWg.Done()
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-stopProgress:
					return
				case <-ticker.C:
					printMu.Lock()
					drawProgress()
					printMu.Unlock()
				}
			}
		}()
	}

	// Step 9: Worker pool
	type job struct {
		word string
	}

	jobs := make(chan job, opts.Threads*2)
	var wg sync.WaitGroup
	var foundRepos []string

	for i := 0; i < opts.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				candidates := buildCandidates(j.word, fuzzWords, opts)
				for _, candidate := range candidates {
					exists, err := checkRepo(username, candidate, opts.IdentityFile, opts.Debug)
					stats.increment()
					if err != nil {
						stats.addError()
						continue
					}

					repoURL := fmt.Sprintf("https://github.com/%s/%s", username, candidate)

					if exists {
						if opts.PrivateOnly && !isPrivateRepo(username, candidate) {
							continue
						}
						stats.addFound()
						printMu.Lock()
						foundRepos = append(foundRepos, repoURL)
						if !opts.NoColor {
							fmt.Printf("\r\x1b[2K"+ansiGreen+"%s"+ansiReset+"\n", repoURL)
						} else {
							fmt.Printf("\r\x1b[2K%s\n", repoURL)
						}
						if !opts.Silent {
							drawProgress()
						}
						if outputFile != nil {
							fmt.Fprintln(outputFile, repoURL)
						}
						printMu.Unlock()
					} else if !opts.ExistingOnly {
						printMu.Lock()
						if !opts.NoColor {
							fmt.Printf("\r\x1b[2K"+ansiYellow+"https://github.com/%s/%s"+ansiReset+"\n", username, candidate)
						} else {
							fmt.Printf("\r\x1b[2Khttps://github.com/%s/%s\n", username, candidate)
						}
						if !opts.Silent {
							drawProgress()
						}
						printMu.Unlock()
					}
				}
			}
		}()
	}

	// Step 10: Feed jobs
	if opts.Word != "" {
		for _, w := range baseWords {
			jobs <- job{word: w}
		}
	} else {
		// Stream from temp file
		f, err := os.Open(tmpFile)
		if err != nil {
			close(jobs)
			return err
		}
		scanner := bufio.NewScanner(f)
		buf := make([]byte, 10*1024*1024)
		scanner.Buffer(buf, len(buf))
		for scanner.Scan() {
			word := strings.TrimSpace(scanner.Text())
			if word != "" {
				jobs <- job{word: word}
			}
		}
		f.Close()
	}

	close(jobs)
	wg.Wait()

	if !opts.Silent {
		close(stopProgress)
		progressWg.Wait()
		elapsed := time.Since(stats.startTime)
		fmt.Printf("\r\x1b[2K:: Progress: [%d/%d] :: Found: %d :: Duration: [%s] :: Errors: %d ::\n",
			atomic.LoadInt64(&stats.checked),
			totalCandidates,
			atomic.LoadInt64(&stats.found),
			formatDuration(elapsed),
			atomic.LoadInt64(&stats.errors),
		)
		fmt.Println()
		fmt.Printf("[*] Scan complete. Found %d repositories.\n", atomic.LoadInt64(&stats.found))
	}

	return nil
}

func runProbeMode(opts *Options) error {
	if err := checkKeyPermissions(opts.IdentityFile); err != nil {
		return err
	}

	// Step 1: Auth check — warning on failure, not fatal
	gologger.Info().Msgf("Checking SSH key: %s", opts.IdentityFile)
	authUser, err := checkSSHKey(opts.IdentityFile)
	if err != nil {
		gologger.Warning().Msgf("SSH key not registered on GitHub: %v — continuing with target username", err)
	} else {
		gologger.Info().Msgf("Authenticated as: %s - https://github.com/%s", authUser, authUser)
		orgs, orgErr := getOrganizations(authUser)
		if orgErr != nil {
			gologger.Warning().Msgf("Could not fetch organizations: %v", orgErr)
		} else {
			for _, org := range orgs {
				gologger.Info().Msgf("Member of organization: %s - https://github.com/%s", org, org)
			}
		}
	}

	// Use the target username from -u flag for all repo operations
	username := opts.Username

	// Step 2: Build word list
	var baseWords []string
	var tmpFile string
	var totalBase int

	if opts.Word != "" {
		word := strings.TrimSpace(opts.Word)
		if !repoNameRegex.MatchString(word) {
			return fmt.Errorf("invalid repository name: %s", word)
		}
		baseWords = []string{word}
		totalBase = 1
	} else {
		gologger.Info().Msgf("Sanitizing and sorting wordlist...")
		var count int
		var wlErr error
		tmpFile, count, wlErr = sanitizeAndSortWordlist(opts.Wordlist)
		if wlErr != nil {
			return wlErr
		}
		totalBase = count
		gologger.Info().Msgf("Wordlist ready: %d valid entries", totalBase)

		cleanup := func() {
			if tmpFile != "" {
				os.Remove(tmpFile)
			}
		}
		defer cleanup()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sigChan
			fmt.Print("\r\x1b[2K")
			gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
			gologger.Warning().Msg("Caught keyboard interrupt (Ctrl-C)")
			gologger.Info().Msg("Cleaning up temporary files...")
			cleanup()
			os.Exit(1)
		}()
	}

	// Step 3: Load fuzz words
	var fuzzWords []string
	if opts.EnableFuzz {
		var fuzzErr error
		fuzzWords, fuzzErr = loadFuzzWords(opts)
		if fuzzErr != nil {
			return fuzzErr
		}
		gologger.Info().Msgf("Fuzz words loaded: %d entries", len(fuzzWords))
	}

	// Step 4: Calculate total candidates
	multiplier := 1
	if opts.EnableFuzz && len(fuzzWords) > 0 {
		multiplier = 1 + len(fuzzWords)
	}
	totalCandidates := int64(totalBase * multiplier)

	// Step 5: Setup output
	var outputFile *os.File
	if opts.OutputEnabled {
		outDir := opts.OutputPath
		if outDir == "" {
			var dirErr error
			outDir, dirErr = os.Getwd()
			if dirErr != nil {
				return fmt.Errorf("cannot determine current directory: %v", dirErr)
			}
		}
		ts := time.Now().Format("20060102_150405")
		outName := fmt.Sprintf("repo_found_%s_%s.txt", username, ts)
		outPath := filepath.Join(outDir, outName)
		var outErr error
		outputFile, outErr = os.Create(outPath)
		if outErr != nil {
			return fmt.Errorf("cannot create output file: %v", outErr)
		}
		defer outputFile.Close()
		gologger.Info().Msgf("Output file: %s", outPath)
	}

	// Step 6: Print config
	if !opts.Silent {
		printConfig(opts, username, int(totalCandidates))
	}

	// Step 7: Setup stats
	stats := &Stats{
		total:     totalCandidates,
		startTime: time.Now(),
	}

	// Step 8: Progress printer
	var printMu sync.Mutex

	drawProgress := func() {
		checked := atomic.LoadInt64(&stats.checked)
		found := atomic.LoadInt64(&stats.found)
		elapsed := time.Since(stats.startTime)
		fmt.Printf("\r\x1b[2K:: Progress: [%d/%d] :: Found: %d :: Duration: [%s] :: Errors: %d ::",
			checked, totalCandidates, found,
			formatDuration(elapsed),
			atomic.LoadInt64(&stats.errors),
		)
	}

	stopProgress := make(chan struct{})
	var progressWg sync.WaitGroup
	if !opts.Silent {
		progressWg.Add(1)
		go func() {
			defer progressWg.Done()
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-stopProgress:
					return
				case <-ticker.C:
					printMu.Lock()
					drawProgress()
					printMu.Unlock()
				}
			}
		}()
	}

	// Step 9: Worker pool
	type job struct {
		word string
	}

	jobs := make(chan job, opts.Threads*2)
	var wg sync.WaitGroup
	var foundRepos []string

	for i := 0; i < opts.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				candidates := buildCandidates(j.word, fuzzWords, opts)
				for _, candidate := range candidates {
					exists, chkErr := checkRepo(username, candidate, opts.IdentityFile, opts.Debug)
					stats.increment()
					if chkErr != nil {
						stats.addError()
						continue
					}

					repoURL := fmt.Sprintf("https://github.com/%s/%s", username, candidate)

					if exists {
						if opts.PrivateOnly && !isPrivateRepo(username, candidate) {
							continue
						}
						stats.addFound()
						printMu.Lock()
						foundRepos = append(foundRepos, repoURL)
						if !opts.NoColor {
							fmt.Printf("\r\x1b[2K"+ansiGreen+"%s"+ansiReset+"\n", repoURL)
						} else {
							fmt.Printf("\r\x1b[2K%s\n", repoURL)
						}
						if !opts.Silent {
							drawProgress()
						}
						if outputFile != nil {
							fmt.Fprintln(outputFile, repoURL)
						}
						printMu.Unlock()
					} else if !opts.ExistingOnly {
						printMu.Lock()
						if !opts.NoColor {
							fmt.Printf("\r\x1b[2K"+ansiYellow+"https://github.com/%s/%s"+ansiReset+"\n", username, candidate)
						} else {
							fmt.Printf("\r\x1b[2Khttps://github.com/%s/%s\n", username, candidate)
						}
						if !opts.Silent {
							drawProgress()
						}
						printMu.Unlock()
					}
				}
			}
		}()
	}

	// Step 10: Feed jobs
	if opts.Word != "" {
		for _, w := range baseWords {
			jobs <- job{word: w}
		}
	} else {
		f, fErr := os.Open(tmpFile)
		if fErr != nil {
			close(jobs)
			return fErr
		}
		scanner := bufio.NewScanner(f)
		buf := make([]byte, 10*1024*1024)
		scanner.Buffer(buf, len(buf))
		for scanner.Scan() {
			word := strings.TrimSpace(scanner.Text())
			if word != "" {
				jobs <- job{word: word}
			}
		}
		f.Close()
	}

	close(jobs)
	wg.Wait()

	if !opts.Silent {
		close(stopProgress)
		progressWg.Wait()
		elapsed := time.Since(stats.startTime)
		fmt.Printf("\r\x1b[2K:: Progress: [%d/%d] :: Found: %d :: Duration: [%s] :: Errors: %d ::\n",
			atomic.LoadInt64(&stats.checked),
			totalCandidates,
			atomic.LoadInt64(&stats.found),
			formatDuration(elapsed),
			atomic.LoadInt64(&stats.errors),
		)
		fmt.Println()
		fmt.Printf("[*] Scan complete. Found %d repositories.\n", atomic.LoadInt64(&stats.found))
	}

	return nil
}

func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%d:%02d:%02d", h, m, s)
}

func main() {
	opts := &Options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("skgre - SSH Key GitHub Repository Enumerator")

	flagSet.CreateGroup("mode", "Mode",
		flagSet.StringVarP(&opts.Mode, "mode", "m", "", "Mode: information | enumeration | probe"),
	)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringVarP(&opts.IdentityFile, "identity-file", "i", "", "Path to SSH private key"),
		flagSet.StringVarP(&opts.Username, "username", "u", "", "Target GitHub username or organization (probe mode)"),
		flagSet.StringVarP(&opts.Word, "word", "w", "", "Single repository name to check"),
		flagSet.StringVarP(&opts.Wordlist, "wordlist", "W", "", "Path to wordlist file"),
	)

	flagSet.CreateGroup("enumeration", "Enumeration",
		flagSet.IntVarP(&opts.Threads, "threads", "t", 10, "Number of concurrent threads"),
		flagSet.BoolVarP(&opts.ExistingOnly, "existing-only", "x", false, "Only show existing repositories"),
		flagSet.BoolVarP(&opts.PrivateOnly, "private-only", "pv", false, "Only show private repositories"),
	)

	flagSet.CreateGroup("fuzzing", "Fuzzing",
		flagSet.BoolVarP(&opts.EnableFuzz, "enable-fuzzing", "F", false, "Enable fuzzing mode"),
		flagSet.BoolVarP(&opts.FuzzBefore, "fuzz-prefix", "fp", false, "Attach fuzz word BEFORE the base word"),
		flagSet.BoolVarP(&opts.FuzzAfter, "fuzz-suffix", "fs", false, "Attach fuzz word AFTER the base word"),
		flagSet.StringVarP(&opts.FuzzWords, "fuzz-words", "fw", "", `Comma-separated fuzz words (e.g. "dev-,prod_,test.")`),
		flagSet.StringVarP(&opts.FuzzFile, "fuzz-wordlist", "ff", "", "Path to fuzz words file (one per line)"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.BoolVarP(&opts.Silent, "silent", "s", false, "Silent mode"),
		flagSet.BoolVarP(&opts.OutputEnabled, "output", "o", false, "Save found repos to file in current directory"),
		flagSet.StringVarP(&opts.OutputPath, "output-path", "op", "", "Directory to save output file (use with -o)"),
		flagSet.BoolVarP(&opts.Debug, "debug", "d", false, "Show raw git ls-remote output (first 5 lines)"),
		flagSet.BoolVarP(&opts.NoColor, "no-color", "nc", false, "Disable colors in output"),
	)
	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("Error parsing flags: %v", err)
	}

	if opts.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}

	// Print banner
	if !opts.Silent {
		printBanner()
	}

	// Mode is required
	if opts.Mode == "" {
		gologger.Error().Msg("Flag -m / -mode is required. Choose one of: information | enumeration | probe")
		os.Exit(1)
	}

	opts.Mode = strings.ToLower(strings.TrimSpace(opts.Mode))
	if opts.Mode != "information" && opts.Mode != "enumeration" && opts.Mode != "probe" {
		gologger.Fatal().Msgf("Invalid mode '%s'. Choose one of: information | enumeration | probe", opts.Mode)
	}

	// Identity file required for all modes
	if opts.IdentityFile == "" {
		gologger.Fatal().Msg("Flag -i / -identity-file is required")
	}

	// Resolve ~ in path
	if strings.HasPrefix(opts.IdentityFile, "~/") {
		home, _ := os.UserHomeDir()
		opts.IdentityFile = filepath.Join(home, opts.IdentityFile[2:])
	}

	// ──────────────────── Mode: information ────────────────────
	if opts.Mode == "information" {
		// Validate that no enumeration-specific flags were passed
		invalidFlags := []string{}
		if opts.Username != "" {
			invalidFlags = append(invalidFlags, "-u / -username")
		}
		if opts.Word != "" {
			invalidFlags = append(invalidFlags, "-w / -word")
		}
		if opts.Wordlist != "" {
			invalidFlags = append(invalidFlags, "-W / -wordlist")
		}
		if opts.EnableFuzz {
			invalidFlags = append(invalidFlags, "-F / -enable-fuzzing")
		}
		if opts.FuzzBefore {
			invalidFlags = append(invalidFlags, "-fp / -fuzz-prefix")
		}
		if opts.FuzzAfter {
			invalidFlags = append(invalidFlags, "-fs / -fuzz-suffix")
		}
		if opts.FuzzWords != "" {
			invalidFlags = append(invalidFlags, "-fw / -fuzz-words")
		}
		if opts.FuzzFile != "" {
			invalidFlags = append(invalidFlags, "-ff / -fuzz-wordlist")
		}
		if opts.ExistingOnly {
			invalidFlags = append(invalidFlags, "-x / -existing-only")
		}
		if opts.Debug {
			invalidFlags = append(invalidFlags, "-d / -debug")
		}

		if len(invalidFlags) > 0 {
			gologger.Fatal().Msgf("Invalid flags for 'information' mode: %s\n  Allowed flags: -i, -s, -o, -h",
				strings.Join(invalidFlags, ", "))
		}

		if !opts.Silent {
			gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
		}
		if err := runInfoMode(opts); err != nil {
			gologger.Fatal().Msg(err.Error())
		}
		return
	}

	// ──────────────────── Mode: probe ────────────────────
	if opts.Mode == "probe" {
		if opts.Username == "" {
			gologger.Fatal().Msg("Flag -u / -username is required in probe mode")
		}

		if opts.Word != "" && opts.Wordlist != "" {
			gologger.Fatal().Msg("Flags -w / -word and -W / -wordlist are mutually exclusive. Use one or the other.")
		}
		if opts.Word == "" && opts.Wordlist == "" {
			gologger.Fatal().Msg("Either -w / -word or -W / -wordlist is required in probe mode")
		}

		if opts.EnableFuzz {
			if !opts.FuzzBefore && !opts.FuzzAfter {
				gologger.Fatal().Msg("When -F / -enable-fuzzing is set, you must specify either -fp / -fuzz-prefix OR -fs / -fuzz-suffix")
			}
			if opts.FuzzBefore && opts.FuzzAfter {
				gologger.Fatal().Msg("Flags -fp / -fuzz-prefix and -fs / -fuzz-suffix are mutually exclusive")
			}
			if opts.FuzzWords == "" && opts.FuzzFile == "" {
				gologger.Fatal().Msg("When fuzzing is enabled, you must provide -fw / -fuzz-words OR -ff / -fuzz-wordlist")
			}
			if opts.FuzzWords != "" && opts.FuzzFile != "" {
				gologger.Fatal().Msg("Flags -fw / -fuzz-words and -ff / -fuzz-wordlist are mutually exclusive")
			}
		}

		if opts.FuzzBefore {
			opts.FuzzAfter = false
		}

		if opts.Threads <= 0 {
			opts.Threads = 10
		}

		if !opts.Silent {
			gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
		}
		if err := runProbeMode(opts); err != nil {
			gologger.Fatal().Msg(err.Error())
		}
		return
	}

	// ──────────────────── Mode: enumeration ────────────────────

	// Reject -u in enumeration mode
	if opts.Username != "" {
		gologger.Fatal().Msg("Flag -u / -username is only valid in probe mode")
	}

	// -w and -W are mutually exclusive
	if opts.Word != "" && opts.Wordlist != "" {
		gologger.Fatal().Msg("Flags -w / -word and -W / -wordlist are mutually exclusive. Use one or the other.")
	}

	// One of -w or -W is required
	if opts.Word == "" && opts.Wordlist == "" {
		gologger.Fatal().Msg("Either -w / -word or -W / -wordlist is required in enumeration mode")
	}

	// Fuzz validation
	if opts.EnableFuzz {
		if !opts.FuzzBefore && !opts.FuzzAfter {
			gologger.Fatal().Msg("When -F / -enable-fuzzing is set, you must specify either -fp / -fuzz-prefix OR -fs / -fuzz-suffix")
		}
		if opts.FuzzBefore && opts.FuzzAfter {
			gologger.Fatal().Msg("Flags -fp / -fuzz-prefix and -fs / -fuzz-suffix are mutually exclusive")
		}
		if opts.FuzzWords == "" && opts.FuzzFile == "" {
			gologger.Fatal().Msg("When fuzzing is enabled, you must provide -fw / -fuzz-words OR -ff / -fuzz-wordlist")
		}
		if opts.FuzzWords != "" && opts.FuzzFile != "" {
			gologger.Fatal().Msg("Flags -fw / -fuzz-words and -ff / -fuzz-wordlist are mutually exclusive")
		}
	}

	// Set fuzz direction
	if opts.FuzzBefore {
		opts.FuzzAfter = false
	}

	if opts.Threads <= 0 {
		opts.Threads = 10
	}

	if !opts.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	}
	if err := runEnumMode(opts); err != nil {
		gologger.Fatal().Msg(err.Error())
	}
}
