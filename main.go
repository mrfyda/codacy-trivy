package main

import (
	"bytes"
	"errors"
	"os"
	"path"

	"github.com/aquasecurity/trivy/pkg/fanal/secret"
	codacy "github.com/codacy/codacy-engine-golang-seed"
	"github.com/samber/lo"
)

const (
	sourceConfigFileName = "trivy.yaml"
)

func readConfiguration(tool codacy.Tool, sourceFolder string) ([]codacy.Pattern, error) {
	// if no patterns, try to use configuration from source code
	// otherwise default configuration file
	if len(tool.Patterns) == 0 {
		sourceConfigFileContent, err := configurationFromSourceCode(sourceFolder)
		if err != nil {
			return nil, err
		}
		return sourceConfigFileContent, nil
	}

	return tool.Patterns, nil
}

func configurationFromSourceCode(sourceFolder string) ([]codacy.Pattern, error) {
	path.Join(sourceFolder, sourceConfigFileName)
	// TODO: Avoid parsing the configuration file and pass it to the tool if it exists
	return nil, nil
}

func runTrivy(patterns []codacy.Pattern, files []string, sourceDir string) ([]codacy.Issue, error) {
	var results []codacy.Issue

	scanner := secret.NewScanner(&secret.Config{
		EnableBuiltinRuleIDs: lo.Map(patterns, func(p codacy.Pattern, index int) string {
			return p.PatternID
		}),
	})

	for _, f := range files {
		content, err := os.ReadFile(path.Join(sourceDir, f))
		if err != nil {
			return nil, errors.New("Error reading file: " + err.Error())
		}
		content = bytes.ReplaceAll(content, []byte("\r"), []byte(""))
		secrets := scanner.Scan(secret.ScanArgs{
			FilePath: f,
			Content:  content,
		})
		for _, result := range secrets.Findings {
			// TODO: Generate 'Suggested fix'
			// TODO: Generate a better Message
			// TODO: Review if PatternIDs should be abstracted to "Secret Scanning"
			results = append(results, codacy.Issue{
				File:      f,
				Message:   result.Title,
				PatternID: result.RuleID,
				Line:      result.StartLine,
			})
		}
	}

	return results, nil
}

type TrivyImplementation struct {
}

func (i TrivyImplementation) Run(tool codacy.Tool, sourceDir string) ([]codacy.Issue, error) {
	patterns, err := readConfiguration(tool, sourceDir)
	if err != nil {
		return nil, errors.New("Error reading configuration: " + err.Error())
	}

	results, err := runTrivy(patterns, tool.Files, sourceDir)
	if err != nil {
		return nil, errors.New("Error running Trivy: " + err.Error())
	}

	return results, nil
}

func main() {
	implementation := TrivyImplementation{}

	codacy.StartTool(implementation)
}